use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use chrono::Utc;
use clap::Parser;
use futures_util::stream::once;
use git2::Repository;
use http_types::{mime, Method};
use multer::Multipart;
use phf::{phf_map, phf_set};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::convert::Infallible;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufRead, BufReader, Write},
    path::PathBuf,
    str::{self, FromStr},
    sync::{Arc, RwLock},
};
use tide::{http::StatusCode, log, Request, Response};
use tide_acme::rustls_acme::caches::DirCache;
use tide_acme::{AcmeConfig, TideRustlsExt};
use tide_websockets::{Message, WebSocket, WebSocketConnection};

mod admin {
    include!(concat!(env!("OUT_DIR"), "/admin.rs"));
}

mod content;
mod nostr;
mod resource;
mod sass;
mod site;
mod template;
mod theme;
mod utils;

use resource::{ContentSource, Resource, ResourceKind};
use site::{load_templates, Site, SiteConfig};
use theme::Theme;

const DEFAULT_ADDR: &str = "0.0.0.0";
const DEFAULT_PORT: u32 = 4884;

const THEMES_REPO: &str = "https://github.com/servus-social/themes";

#[derive(Parser)]
struct Cli {
    #[clap(short('e'), long)]
    contact_email: Option<String>,

    #[clap(short('c'), long)]
    ssl_cert: Option<String>,

    #[clap(short('k'), long)]
    ssl_key: Option<String>,

    #[clap(short('s'), long)]
    ssl_acme: bool,

    #[clap(long)]
    ssl_acme_production: bool,

    #[clap(short('b'), long)]
    bind: Option<String>,

    #[clap(short('p'), long)]
    port: Option<u32>,
}

#[derive(Clone)]
struct State {
    themes: Arc<RwLock<HashMap<String, Theme>>>,
    sites: Arc<RwLock<HashMap<String, Site>>>,
}

#[derive(Deserialize, Serialize)]
struct PostSiteRequestBody {
    domain: String,
}

#[derive(Deserialize, Serialize)]
struct PutSiteConfigRequestBody {
    theme: String,
}

static NIP96_CONTENT_TYPES: phf::Map<&'static str, &'static str> = phf_map! {
    "image/png" => "png",
    "image/jpeg" => "jpg",
    "image/gif" => "gif",
    "audio/mpeg" => "mp3",
};

static BLOSSOM_CONTENT_TYPES: phf::Set<&'static str> = phf_set! {
    "audio/mpeg",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
};

#[derive(Debug, Deserialize, Serialize)]
struct FileMetadata {
    sha256: String,
    #[serde(rename = "type")]
    content_type: String,
    size: usize,
    url: String,
}

fn build_raw_response(content: Vec<u8>, mime: mime::Mime) -> Response {
    Response::builder(StatusCode::Ok)
        .content_type(mime)
        .header("Access-Control-Allow-Origin", "*")
        .body(&*content)
        .build()
}

fn get_resource(site: &Site, resource_path: &str) -> Resource {
    let resources = site.resources.read().unwrap();
    resources.get(resource_path).unwrap().clone()
}

fn render_and_build_response(site: &Site, resource: Resource) -> tide::Result<Response> {
    match resource.render(site) {
        Ok(response) => Ok(Response::builder(StatusCode::Ok)
            .content_type(mime::HTML)
            .header("Access-Control-Allow-Origin", "*")
            .body(response)
            .build()),
        Err(e) => Err(tide::Error::new(StatusCode::BadRequest, e)),
    }
}

async fn handle_websocket(
    request: Request<State>,
    mut ws: WebSocketConnection,
) -> tide::Result<()> {
    while let Some(Ok(Message::Text(message))) = async_std::stream::StreamExt::next(&mut ws).await {
        log::debug!("WS RECV: {}", message);
        let nostr_message = nostr::Message::from_str(&message);
        if nostr_message.is_err() {
            log::warn!("Cannot parse: {}", message);
            continue;
        }
        match nostr_message.unwrap() {
            nostr::Message::Event { event } => {
                {
                    if let Some(site) = get_site(&request) {
                        if let Some(site_pubkey) = site.config.pubkey {
                            if event.pubkey != site_pubkey {
                                log::info!("Ignoring event for unknown pubkey: {}.", event.pubkey);
                                continue;
                            }
                        } else {
                            log::info!("Ignoring event because site has no pubkey.");
                            continue;
                        }
                    } else {
                        return Ok(());
                    }
                }

                if event.validate_sig().is_err() {
                    log::info!("Ignoring invalid event.");
                    continue;
                }

                if let Some(site) = get_site(&request) {
                    if event.kind == nostr::EVENT_KIND_DELETE {
                        let post_removed = site.remove_content(&event);
                        log::info!(
                            "Incoming DELETE event: {}. status: {}",
                            event.id,
                            post_removed
                        );
                        ws.send_json(&json!(vec![
                            serde_json::Value::String("OK".to_string()),
                            serde_json::Value::String(event.id.to_string()),
                            serde_json::Value::Bool(post_removed),
                            serde_json::Value::String("".to_string())
                        ]))
                        .await
                        .unwrap();
                    } else {
                        site.add_content(&event);
                        log::info!("Incoming event: {}.", event.id);
                        ws.send_json(&json!(vec![
                            serde_json::Value::String("OK".to_string()),
                            serde_json::Value::String(event.id.to_string()),
                            serde_json::Value::Bool(true),
                            serde_json::Value::String("".to_string())
                        ]))
                        .await
                        .unwrap();
                    }
                } else {
                    return Ok(());
                }
            }
            nostr::Message::Req { sub_id, filters } => {
                let mut events: Vec<nostr::Event> = vec![]; // Hashmap? (unique)

                if let Some(site) = get_site(&request) {
                    let site_pubkey = site.config.pubkey.unwrap();
                    for filter in filters.iter() {
                        for (k, _) in &filter.extra {
                            log::warn!("Ignoring unknown filter: {}.", k);
                        }

                        log::info!("Requested filter: {}", filter);

                        if filter.matches_author(&site_pubkey) {
                            for event_ref in site.events.read().unwrap().values() {
                                if filter.matches_kind(&event_ref.kind)
                                    && filter.matches_time(&event_ref.created_at)
                                {
                                    if let Some((front_matter, content)) = event_ref.read() {
                                        if let Some(event) =
                                            nostr::parse_event(&front_matter, &content)
                                        {
                                            if filter.matches_author(&event.pubkey) {
                                                events.push(event);
                                                if let Some(limit) = filter.limit {
                                                    if events.len() >= limit {
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    return Ok(());
                }

                for event in &events {
                    ws.send_json(&json!([
                        serde_json::Value::String("EVENT".to_string()),
                        serde_json::Value::String(sub_id.to_string()),
                        event.to_json(),
                    ]))
                    .await
                    .unwrap();
                }
                ws.send_json(&json!(vec!["EOSE", &sub_id.to_string()]))
                    .await
                    .unwrap();
                log::info!(
                    "Sent {} events back for subscription {}.",
                    events.len(),
                    sub_id
                );
                // TODO: At this point we should save the subscription and notify this client later if other posts appear.
                // For that, we probably need to introduce a dispatcher thread.
                // See: https://stackoverflow.com/questions/35673702/chat-using-rust-websocket/35785414#35785414
            }
            nostr::Message::Close { .. } => {
                // Nothing to do here, since we don't actually store subscriptions!
            }
        }
    }
    Ok(())
}

async fn handle_index(request: Request<State>) -> tide::Result<Response> {
    if let Some(site) = get_site(&request) {
        let resources = site.resources.read().unwrap();
        match resources.get("/index") {
            Some(..) => render_and_build_response(&site, get_resource(&site, "/index")),
            None => render_and_build_response(&site, get_default_index()),
        }
    } else {
        return Err(tide::Error::from_str(StatusCode::NotFound, ""));
    }
}

fn get_empty_site(theme: &str) -> Result<Site> {
    let mut config = SiteConfig::empty(&format!("http://localhost:{}", DEFAULT_PORT), theme);
    let theme_config = theme::load_config(&format!("./themes/{}/config.toml", theme))?;
    config.merge(&theme_config);
    let tera = load_templates(&config)?;
    Ok(Site {
        domain: "localhost".to_string(),
        config,
        data: Arc::new(RwLock::new(HashMap::new())),
        events: Arc::new(RwLock::new(HashMap::new())),
        resources: Arc::new(RwLock::new(HashMap::new())),
        tera: Arc::new(RwLock::new(tera)),
    })
}

fn get_default_index() -> Resource {
    Resource {
        kind: ResourceKind::Page,
        slug: "index".to_string(),
        title: Some("".to_string()),
        date: Utc::now().naive_utc(),
        content_source: ContentSource::String("Servus, world!".to_string()),
    }
}

fn get_site(request: &Request<State>) -> Option<Site> {
    let host = request.host().unwrap().to_string();
    let sites = request.state().sites.read().unwrap();

    if !sites.contains_key(&host) {
        if sites.len() == 1 {
            return Some(sites.values().into_iter().next().unwrap().clone());
        } else {
            return None;
        }
    } else {
        return sites.get(&host).cloned();
    }
}

async fn handle_request(request: Request<State>) -> tide::Result<Response> {
    let mut path = request.param("path").unwrap();
    if path.ends_with('/') {
        path = path.strip_suffix('/').unwrap();
    }

    if path == ".admin" {
        let admin_index = admin::INDEX_HTML.replace(
            "%%API_BASE_URL%%",
            &format!("//{}", request.host().unwrap()),
        );
        return Ok(Response::builder(StatusCode::Ok)
            .content_type(mime::HTML)
            .body(admin_index)
            .build());
    }

    if path == ".well-known/nostr/nip96.json" {
        let nip96_json = format!(
            "{{ \"api_url\": \"https://{}/api/files\", \"download_url\": \"https://{}/\" }}",
            request.host().unwrap(),
            request.host().unwrap()
        );
        return Ok(Response::builder(StatusCode::Ok)
            .content_type(mime::JSON)
            .body(nip96_json)
            .build());
    }

    let mut part: Option<String> = None;
    if path.contains(".") {
        let parts = path.split(".").collect::<Vec<_>>();
        if parts.len() == 2 {
            part = Some(parts[0].to_string());
        }
    } else {
        part = Some(path.to_string());
    }
    let mut sha256: Option<String> = None;
    if let Some(part) = part {
        if part.len() == 64 && part.chars().all(|c| char::is_ascii_alphanumeric(&c)) {
            sha256 = Some(part.to_string());
        }
    }

    if sha256.is_some() && request.method() == Method::Options {
        return Ok(Response::builder(StatusCode::Ok)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Authorization,*")
            .header("Access-Control-Allow-Methods", "GET,PUT,DELETE")
            .build());
    }

    if let Some(site) = get_site(&request) {
        if let Some((mime, response)) = resource::render_standard_resource(path, &site) {
            return Ok(Response::builder(StatusCode::Ok)
                .content_type(mime)
                .header("Access-Control-Allow-Origin", "*")
                .body(response)
                .build());
        }

        let site_resources: Vec<String>;
        {
            let resources = site.resources.read().unwrap();
            site_resources = resources.keys().cloned().collect();
        }

        let themes = request.state().themes.read().unwrap();
        let theme = themes.get(&site.config.theme).unwrap();

        let mut resource_path = format!("/{}", &path);
        if site_resources.contains(&resource_path) {
            return render_and_build_response(&site, get_resource(&site, &resource_path));
        } else {
            let theme_resources = theme.resources.read().unwrap();
            if theme_resources.contains_key(&resource_path) {
                let content = theme_resources.get(&resource_path).unwrap();
                let guess = mime_guess::from_path(resource_path);
                let mime = mime::Mime::from_str(guess.first().unwrap().essence_str()).unwrap();
                return Ok(build_raw_response(content.as_bytes().to_vec(), mime));
            }
            resource_path = format!("{}/index", &resource_path);
            if site_resources.contains(&resource_path) {
                return render_and_build_response(&site, get_resource(&site, &resource_path));
            } else {
                resource_path = format!("{}/{}/{}", site::SITE_PATH, site.domain, path);
                for part in resource_path.split('/').collect::<Vec<_>>() {
                    let first_char = part.chars().next().unwrap();
                    if first_char == '_' || (first_char == '.' && part.len() > 1) {
                        return Err(tide::Error::from_str(StatusCode::NotFound, ""));
                    }
                }
                if PathBuf::from(&resource_path).exists() {
                    // look for a static file
                    let raw_content = fs::read(&resource_path).unwrap();
                    let guess = mime_guess::from_path(resource_path);
                    let mime = mime::Mime::from_str(guess.first().unwrap().essence_str()).unwrap();
                    return Ok(build_raw_response(raw_content, mime));
                } else {
                    // look for an uploaded file
                    if let Some(sha256) = sha256 {
                        resource_path = format!(
                            "{}/{}/_content/files/{}",
                            site::SITE_PATH,
                            site.domain,
                            sha256
                        );
                        if PathBuf::from(&resource_path).exists() {
                            let raw_content = fs::read(&resource_path).unwrap();
                            let metadata_file = File::open(&format!(
                                "{}/{}/_content/files/{}.metadata.json",
                                site::SITE_PATH,
                                site.domain,
                                sha256
                            ))
                            .unwrap();
                            let metadata_reader = BufReader::new(metadata_file);
                            let metadata: FileMetadata =
                                serde_json::from_reader(metadata_reader).unwrap();
                            let mime = mime::Mime::from_str(&metadata.content_type).unwrap();
                            return Ok(build_raw_response(raw_content, mime));
                        } else {
                            return Err(tide::Error::from_str(StatusCode::NotFound, ""));
                        }
                    } else {
                        return Err(tide::Error::from_str(StatusCode::NotFound, ""));
                    }
                }
            }
        }
    } else {
        return Err(tide::Error::from_str(StatusCode::NotFound, ""));
    }
}

fn get_nostr_auth_event(request: &Request<State>) -> Option<nostr::Event> {
    let auth_header = request.header(tide::http::headers::AUTHORIZATION);
    let parts = auth_header?.as_str().split(' ').collect::<Vec<_>>();
    if parts.len() != 2 {
        return None;
    }
    if parts[0].to_lowercase() != "nostr" {
        return None;
    }

    Some(
        serde_json::from_str(str::from_utf8(&STANDARD.decode(parts[1]).unwrap()).unwrap()).unwrap(),
    )
}

fn get_pubkey(request: &Request<State>) -> Option<String> {
    Some(request.param("pubkey").unwrap().to_string())
}

fn nostr_auth(request: &Request<State>) -> Option<String> {
    get_nostr_auth_event(request)?
        .get_nip98_pubkey(request.url().as_str(), request.method().as_ref())
}

fn blossom_upload_auth(request: &Request<State>) -> Option<String> {
    blossom_auth(request, "upload")
}

fn blossom_delete_auth(request: &Request<State>) -> Option<String> {
    blossom_auth(request, "delete")
}

fn blossom_auth(request: &Request<State>, method: &str) -> Option<String> {
    get_nostr_auth_event(request)?.get_blossom_pubkey(method)
}

async fn handle_post_site(mut request: Request<State>) -> tide::Result<Response> {
    let domain = request
        .body_json::<PostSiteRequestBody>()
        .await
        .unwrap()
        .domain;
    let state = &request.state();

    if state.sites.read().unwrap().contains_key(&domain) {
        Err(tide::Error::from_str(
            StatusCode::Conflict,
            "Site already exists!",
        ))
    } else {
        let key = nostr_auth(&request);
        if key.is_none() {
            return Err(tide::Error::from_str(
                StatusCode::BadRequest,
                "Missing Nostr auth!",
            ));
        }

        match site::create_site(&domain, key) {
            Ok(site) => {
                let sites = &mut state.sites.write().unwrap();
                sites.insert(domain, site);

                Ok(Response::builder(StatusCode::Ok)
                    .content_type(mime::JSON)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(json!({}).to_string())
                    .build())
            }
            Err(e) => {
                log::warn!("Error creating site {}: {}", &domain, e);
                Err(tide::Error::new(StatusCode::BadRequest, e))
            }
        }
    }
}

async fn handle_get_sites(request: Request<State>) -> tide::Result<Response> {
    let key = nostr_auth(&request);
    if key.is_none() {
        return Err(tide::Error::from_str(
            StatusCode::BadRequest,
            "Missing Nostr auth!",
        ));
    }
    let key = key.unwrap();
    let all_sites = &request.state().sites.read().unwrap();
    let sites = all_sites
        .iter()
        .filter_map(|s| {
            if s.1.config.pubkey.clone().unwrap() == key {
                Some(HashMap::from([("domain", s.0)]))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    Ok(Response::builder(StatusCode::Ok)
        .content_type(mime::JSON)
        .body(json!(sites).to_string())
        .build())
}

async fn handle_get_site_config(request: Request<State>) -> tide::Result<Response> {
    let site = {
        if let Some(site) = get_site(&request) {
            if !is_authorized(&request, &site, &nostr_auth) {
                return Ok(Response::builder(StatusCode::Forbidden)
                    .header("Access-Control-Allow-Origin", "*")
                    .build());
            }
            site
        } else {
            return Err(tide::Error::from_str(StatusCode::NotFound, ""));
        }
    };

    let themes: Vec<String> = request
        .state()
        .themes
        .read()
        .unwrap()
        .keys()
        .cloned()
        .collect();

    Ok(Response::builder(StatusCode::Ok)
        .content_type(mime::JSON)
        .body(json!({"theme": site.config.theme, "available_themes": themes}).to_string())
        .build())
}

async fn handle_put_site_config(mut request: Request<State>) -> tide::Result<Response> {
    let site = {
        if let Some(site) = get_site(&request) {
            if !is_authorized(&request, &site, &nostr_auth) {
                return Ok(Response::builder(StatusCode::Forbidden)
                    .header("Access-Control-Allow-Origin", "*")
                    .build());
            }
            site
        } else {
            return Err(tide::Error::from_str(StatusCode::NotFound, ""));
        }
    };

    let config_path = format!("{}/{}/_config.toml", site::SITE_PATH, site.domain);
    let mut config = site::load_config(&config_path).unwrap();

    let old_theme = config.theme;

    // NB: we need to load config from the file rather than using the one already loaded,
    // which is already merged with the theme's config! That means... we need to save it first!
    // TODO: How can this be improved?
    config.theme = request
        .body_json::<PutSiteConfigRequestBody>()
        .await
        .unwrap()
        .theme;
    site::save_config(&config_path, &config);

    match site::load_site(&site.domain) {
        Ok(new_site) => {
            let state = request.state();
            let sites = &mut state.sites.write().unwrap();
            sites.remove(&site.domain);
            sites.insert(site.domain, new_site);

            Ok(Response::builder(StatusCode::Ok)
                .content_type(mime::JSON)
                .body(json!({}).to_string())
                .build())
        }
        Err(e) => {
            log::warn!(
                "Failed to switch theme to {} for site {}: {}",
                config.theme,
                site.domain,
                e
            );
            config.theme = old_theme;
            site::save_config(&config_path, &config);
            Err(tide::Error::from_str(
                StatusCode::InternalServerError,
                "Failed to change theme!",
            ))
        }
    }
}

async fn handle_blossom_list_request(request: Request<State>) -> tide::Result<Response> {
    let site_path = {
        if let Some(site) = get_site(&request) {
            if !is_authorized(&request, &site, &get_pubkey) {
                return Ok(Response::builder(StatusCode::Forbidden)
                    .header("Access-Control-Allow-Origin", "*")
                    .build());
            }
            format!("{}/{}", site::SITE_PATH, site.domain)
        } else {
            return Err(tide::Error::from_str(StatusCode::NotFound, ""));
        }
    };

    let paths = match fs::read_dir(format!("{}/_content/files", site_path)) {
        Ok(paths) => paths.map(|r| r.unwrap()).collect(),
        _ => vec![],
    };

    let mut list = vec![];

    for path in &paths {
        if path.path().extension().is_none() {
            let mut metadata_path = path.path();
            metadata_path.set_extension("metadata.json");
            let metadata_file = File::open(&metadata_path).unwrap();
            let metadata_reader = BufReader::new(metadata_file);
            let metadata: FileMetadata = serde_json::from_reader(metadata_reader).unwrap();
            list.push(metadata);
        }
    }

    return Ok(Response::builder(StatusCode::Created)
        .content_type(mime::JSON)
        .header("Access-Control-Allow-Origin", "*")
        .body(serde_json::to_string(&list).unwrap())
        .build());
}

fn is_authorized(
    request: &Request<State>,
    site: &Site,
    get_pubkey: &dyn Fn(&Request<State>) -> Option<String>,
) -> bool {
    if let Some(pubkey) = get_pubkey(&request) {
        if let Some(site_pubkey) = site.config.pubkey.to_owned() {
            if site_pubkey != pubkey {
                log::info!("Non-matching key.");
                return false;
            }
        } else {
            log::info!("The site has no pubkey.");
            return false;
        }
    } else {
        log::info!("Missing auth header.");
        return false;
    }

    return true;
}

fn write_file<C>(
    site_path: &str,
    host: &str,
    hash: &str,
    mime: &http_types::mime::Mime,
    size: usize,
    content: C,
) -> FileMetadata
where
    C: AsRef<[u8]>,
{
    let metadata = FileMetadata {
        sha256: hash.to_owned(),
        content_type: mime.essence().to_owned(),
        size,
        url: format!("https://{}/{}", host, hash),
    };

    fs::create_dir_all(format!("{}/_content/files", site_path)).unwrap();
    fs::write(format!("{}/_content/files/{}", site_path, hash), content).unwrap();
    fs::write(
        format!("{}/_content/files/{}.metadata.json", site_path, hash),
        serde_json::to_string(&metadata).unwrap(),
    )
    .unwrap();

    metadata
}

fn delete_file(site_path: &str, hash: &str) {
    fs::remove_file(format!("{}/_content/files/{}", site_path, hash)).unwrap();
    fs::remove_file(format!(
        "{}/_content/files/{}.metadata.json",
        site_path, hash
    ))
    .unwrap();
}

async fn handle_nip96_upload_request(mut request: Request<State>) -> tide::Result<Response> {
    if request.method() == Method::Options {
        return Ok(Response::builder(StatusCode::Ok)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Authorization")
            .build());
    }

    let site_path = {
        if let Some(site) = get_site(&request) {
            if !is_authorized(&request, &site, &nostr_auth) {
                return Ok(Response::builder(StatusCode::Forbidden)
                    .header("Access-Control-Allow-Origin", "*")
                    .build());
            }
            format!("{}/{}", site::SITE_PATH, site.domain)
        } else {
            return Err(tide::Error::from_str(StatusCode::NotFound, ""));
        }
    };

    let content_type = request
        .header(tide::http::headers::CONTENT_TYPE)
        .unwrap()
        .as_str();
    let boundary_index = content_type.find("boundary=").unwrap();
    let boundary: String = content_type
        .chars()
        .skip(boundary_index)
        .skip("boundary=".len())
        .collect();
    let bytes = request.body_bytes().await?;
    let stream = once(async move { Result::<Bytes, Infallible>::Ok(Bytes::from(bytes)) });
    let mut multipart = Multipart::new(stream, boundary);
    while let Some(field) = multipart.next_field().await.unwrap() {
        if field.name().unwrap() == "file" {
            let content = field.bytes().await.unwrap();
            let hash = sha256::digest(&*content);
            let mime = mime::Mime::sniff(&content);
            if mime.is_err() || !NIP96_CONTENT_TYPES.contains_key(mime.as_ref().unwrap().essence())
            {
                return Ok(Response::builder(StatusCode::BadRequest)
                    .content_type(mime::JSON)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(json!({"status": "error", "message": "Unknown content type."}))
                    .build());
            }

            let metadata = write_file(
                &site_path,
                request.host().unwrap(),
                &hash,
                &mime.unwrap(),
                content.len(),
                content,
            );

            return Ok(Response::builder(StatusCode::Created)
               .content_type(mime::JSON)
               .header("Access-Control-Allow-Origin", "*")
               .body(json!({"status": "success", "nip94_event": {"tags": [["url", metadata.url], ["ox", hash]]}}).to_string())
               .build());
        }
    }

    Ok(Response::builder(StatusCode::BadRequest)
        .content_type(mime::JSON)
        .header("Access-Control-Allow-Origin", "*")
        .body(json!({"status": "error", "message": "File not found."}))
        .build())
}

async fn handle_nip96_delete_request(request: Request<State>) -> tide::Result<Response> {
    let site_path = {
        if let Some(site) = get_site(&request) {
            if !is_authorized(&request, &site, &nostr_auth) {
                return Err(tide::Error::from_str(StatusCode::Forbidden, ""));
            }
            format!("{}/{}", site::SITE_PATH, site.domain)
        } else {
            return Err(tide::Error::from_str(StatusCode::NotFound, ""));
        }
    };

    delete_file(&site_path, request.param("sha256").unwrap());

    return Ok(Response::builder(StatusCode::Ok)
        .content_type(mime::JSON)
        .body(json!({ "status": "success" }))
        .build());
}

async fn handle_blossom_upload_request(mut request: Request<State>) -> tide::Result<Response> {
    if request.method() == Method::Options {
        return Ok(Response::builder(StatusCode::Ok)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Authorization,*")
            .header("Access-Control-Allow-Methods", "GET,PUT,DELETE")
            .build());
    }

    let site_path = {
        if let Some(site) = get_site(&request) {
            if !is_authorized(&request, &site, &blossom_upload_auth) {
                return Ok(Response::builder(StatusCode::Unauthorized)
                    .header("Access-Control-Allow-Origin", "*")
                    .build());
            }
            format!("{}/{}", site::SITE_PATH, site.domain)
        } else {
            return Err(tide::Error::from_str(StatusCode::NotFound, ""));
        }
    };

    let bytes = request.body_bytes().await?;

    let hash = sha256::digest(&*bytes);

    let mime = mime::Mime::sniff(&bytes);
    if mime.is_err() || !BLOSSOM_CONTENT_TYPES.contains(mime.as_ref().unwrap().essence()) {
        return Ok(Response::builder(StatusCode::BadRequest)
            .content_type(mime::JSON)
            .header("Access-Control-Allow-Origin", "*")
            .body(json!({"message": "Unknown content type."}))
            .build());
    }

    let metadata = write_file(
        &site_path,
        request.host().unwrap(),
        &hash,
        &mime.unwrap(),
        bytes.len(),
        bytes,
    );

    return Ok(Response::builder(StatusCode::Created)
        .content_type(mime::JSON)
        .header("Access-Control-Allow-Origin", "*")
        .body(serde_json::to_string(&metadata).unwrap())
        .build());
}

async fn handle_blossom_delete_request(request: Request<State>) -> tide::Result<Response> {
    let site_path = {
        if let Some(site) = get_site(&request) {
            if !is_authorized(&request, &site, &blossom_delete_auth) {
                return Ok(Response::builder(StatusCode::Unauthorized)
                    .header("Access-Control-Allow-Origin", "*")
                    .build());
            }
            format!("{}/{}", site::SITE_PATH, site.domain)
        } else {
            return Err(tide::Error::from_str(StatusCode::NotFound, ""));
        }
    };

    delete_file(&site_path, request.param("sha256").unwrap());

    return Ok(Response::builder(StatusCode::Ok)
        .content_type(mime::JSON)
        .header("Access-Control-Allow-Origin", "*")
        .body(json!({}))
        .build());
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    let args = Cli::parse();

    femme::with_level(log::LevelFilter::Info);

    let mut themes = theme::load_themes();

    if themes.len() == 0 {
        log::error!("No themes found!");

        let stdin = io::stdin();
        let mut response = String::new();
        while response != "n" && response != "y" {
            print!("Fetch themes from {}? [y/n]? ", THEMES_REPO);
            io::stdout().flush().unwrap();
            response = stdin.lock().lines().next().unwrap().unwrap().to_lowercase();
        }

        if response == "y" {
            let url = format!("{}.git", THEMES_REPO);
            match Repository::clone(&url, "./themes") {
                Ok(repo) => {
                    let mut failed_to_clone_themes = 0;
                    let mut failed_to_load_themes = 0;
                    let mut failed_to_render_themes = 0;
                    let mut usable_themes = 0;

                    for mut submodule in repo.submodules().unwrap() {
                        let theme: String =
                            (*submodule.path().as_os_str().to_str().unwrap()).to_string();
                        let theme_directory = format!("./themes/{}", theme);

                        log::info!("Cloning theme: {}...", theme);
                        if let Err(e) = submodule.update(true, None) {
                            log::warn!("Failed to clone theme {}: {}", theme, e);
                            let _ = fs::remove_dir_all(theme_directory);
                            failed_to_clone_themes += 1;
                            continue;
                        };

                        match get_empty_site(&theme) {
                            Err(e) => {
                                log::warn!("Failed to load theme {}: {}", theme, e);
                                let _ = fs::remove_dir_all(theme_directory);
                                failed_to_load_themes += 1;
                                continue;
                            }
                            Ok(site) => {
                                match render_and_build_response(&site, get_default_index()) {
                                    Err(e) => {
                                        log::warn!("Failed to render theme {}: {}", theme, e);
                                        let _ = fs::remove_dir_all(theme_directory);
                                        failed_to_render_themes += 1;
                                        continue;
                                    }
                                    _ => {
                                        log::info!("Usable theme: {}!", theme);
                                        usable_themes += 1;
                                    }
                                }
                            }
                        }
                    }

                    log::info!("Usable themes: {}. Failed to clone themes: {}. Failed to load themes: {}. Failed to render themes: {}. ", usable_themes, failed_to_clone_themes, failed_to_load_themes, failed_to_render_themes);
                }
                Err(e) => panic!("Failed to clone themes repo: {}", e),
            };
        } else {
            return Ok(());
        }

        themes = theme::load_themes();

        if themes.len() == 0 {
            panic!("No themes!");
        }
    }

    let sites;

    let existing_sites = site::load_sites();

    if existing_sites.len() == 0 {
        let stdin = io::stdin();
        let mut response = String::new();
        while response != "n" && response != "y" {
            print!("No sites found. Create a default site [y/n]? ");
            io::stdout().flush().unwrap();
            response = stdin.lock().lines().next().unwrap().unwrap().to_lowercase();
        }

        if response == "y" {
            print!("Domain: ");
            io::stdout().flush().unwrap();
            let domain = stdin.lock().lines().next().unwrap().unwrap().to_lowercase();
            print!("Admin pubkey: ");
            io::stdout().flush().unwrap();
            let admin_pubkey = stdin.lock().lines().next().unwrap().unwrap().to_lowercase();
            let site = site::create_site(&domain, Some(admin_pubkey)).unwrap();

            sites = [(domain, site)].iter().cloned().collect();
        } else {
            sites = HashMap::new();
        }
    } else {
        sites = existing_sites;
    }

    let site_count = sites.len();

    let mut app = tide::with_state(State {
        themes: Arc::new(RwLock::new(themes)),
        sites: Arc::new(RwLock::new(sites)),
    });

    app.with(log::LogMiddleware::new());
    app.at("/")
        .with(WebSocket::new(handle_websocket))
        .get(handle_index);
    app.at("*path").options(handle_request).get(handle_request);

    // API
    app.at("/api/sites")
        .post(handle_post_site)
        .get(handle_get_sites);

    // Site API
    app.at("/api/config")
        .get(handle_get_site_config)
        .put(handle_put_site_config);

    // Blossom API
    app.at("/upload")
        .options(handle_blossom_upload_request)
        .put(handle_blossom_upload_request);
    app.at("/list/:pubkey").get(handle_blossom_list_request);
    app.at("/:sha256").delete(handle_blossom_delete_request);

    // NIP-96 API
    app.at("/api/files")
        .options(handle_nip96_upload_request)
        .post(handle_nip96_upload_request);
    app.at("/api/files/:sha256")
        .delete(handle_nip96_delete_request);

    let addr = args.bind.unwrap_or(DEFAULT_ADDR.to_string());

    if args.ssl_cert.is_some() && args.ssl_key.is_some() {
        let port = args.port.unwrap_or(443);
        let bind_to = format!("{addr}:{port}");
        let mut listener = tide_rustls::TlsListener::build().addrs(bind_to);
        listener = listener
            .cert(args.ssl_cert.unwrap())
            .key(args.ssl_key.unwrap());
        app.listen(listener).await?;
    } else if args.ssl_acme || args.ssl_acme_production {
        if args.contact_email.is_none() {
            panic!("Use -e to provide a contact email!");
        }
        let domains: Vec<String> = app
            .state()
            .sites
            .read()
            .unwrap()
            .keys()
            .map(|x| x.to_string())
            .collect();
        let cache = DirCache::new("./cache");
        let acme_config = AcmeConfig::new(domains)
            .cache(cache)
            .directory_lets_encrypt(args.ssl_acme_production)
            .contact_push(format!("mailto:{}", args.contact_email.unwrap()));
        let port = args.port.unwrap_or(443);
        let bind_to = format!("{addr}:{port}");
        let mut listener = tide_rustls::TlsListener::build().addrs(bind_to);
        listener = listener.acme(acme_config);
        if !args.ssl_acme_production {
            println!("NB: Using Let's Encrypt STAGING environment! Great for testing, but browsers will complain about the certificate.");
        }
        app.listen(listener).await?;
    } else {
        let port = args.port.unwrap_or(DEFAULT_PORT);
        let bind_to = format!("{addr}:{port}");
        println!("####################################");
        if site_count == 1 {
            println!("*** Your site: http://localhost:{port}/ ***");
        }
        println!("*** The admin interface: http://localhost:{port}/.admin/ ***");
        println!("####################################");
        app.listen(bind_to).await?;
    };

    Ok(())
}
