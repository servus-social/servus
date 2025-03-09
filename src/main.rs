use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::Bytes;
use chrono::Utc;
use clap::Parser;
use futures_util::stream::once;
use http_types::{mime, Method};
use multer::Multipart;
use phf::{phf_map, phf_set};
use reqwest::blocking::get;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::convert::Infallible;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufRead, BufReader, Write},
    path::Path,
    str::{self, FromStr},
    sync::{Arc, RwLock},
};
use tide::{http::StatusCode, log, Request, Response, Server};
use tide_acme::rustls_acme::caches::DirCache;
use tide_acme::{AcmeConfig, TideRustlsExt};
use tide_websockets::{Message, WebSocket, WebSocketConnection};
use zip::ZipArchive;

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

use resource::{
    ListingSectionFilter, NoteSectionFilter, Page, PictureSectionFilter, PostSectionFilter,
    Renderable, Resource, ResourceKind, Section,
};
use site::Site;
use theme::{Theme, ThemeConfig};

const DEFAULT_THEMES_URL: &str =
    "https://github.com/servus-social/themes/releases/latest/download/themes.zip";

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

    #[clap(short('t'), long)]
    themes_url: Option<String>,

    #[clap(short('v'), long)]
    validate_themes: bool,
}

#[derive(Clone)]
struct State {
    root_path: String,
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

fn render_and_build_response<T: Renderable>(site: &Site, renderable: T) -> tide::Result<Response> {
    match renderable.render(site) {
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
                                    let Some((front_matter, content)) = event_ref.read() else {
                                        continue;
                                    };
                                    let Some(event) = nostr::parse_event(&front_matter, &content)
                                    else {
                                        continue;
                                    };
                                    if filter.matches_id(&event.id)
                                        && filter.matches_author(&event.pubkey)
                                    {
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

async fn handle_index<R: Renderable>(request: Request<State>) -> tide::Result<Response> {
    if let Some(site) = get_site(&request) {
        let resources = site.resources.read().unwrap();
        let mut slug = request.url().path_segments().unwrap().last().unwrap();
        if slug == "" {
            slug = "index";
        }
        if let Some(r) = resources.get(&format!("/{}", slug)) {
            render_and_build_response(&site, R::from_resource(&r, &site))
        } else {
            render_and_build_response(&site, R::from_resource(&get_default_index(slug), &site))
        }
    } else {
        Err(tide::Error::from_str(StatusCode::NotFound, ""))
    }
}

fn get_default_index(slug: &str) -> Resource {
    Resource {
        kind: ResourceKind::Page,
        slug: slug.to_string(),
        title: Some("".to_string()),
        date: Utc::now().naive_utc(),
        event_id: None,
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
    let mut path = request.param("path")?;
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

        let mut resource_path = format!("/{}", &path);

        let mut page: Option<Page> = None;
        let mut section: Option<Section<PostSectionFilter>> = None;
        {
            let resources = site.resources.read().unwrap();
            if let Some(r) = resources.get(&resource_path) {
                page = Some(Page::from_resource(r, &site));
            } else if let Some(r) = resources.get(&format!("{}/index", &resource_path)) {
                section = Some(Section::from_resource(r, &site));
            }
        };

        let themes = request.state().themes.read().unwrap();
        let theme = themes.get(&site.config.theme).unwrap();

        if let Some(page) = page {
            return render_and_build_response(&site, page);
        } else if let Some(section) = section {
            return render_and_build_response(&site, section);
        } else {
            let theme_resources = theme.resources.read().unwrap();
            if let Some(content) = theme_resources.get(&resource_path) {
                let guess = mime_guess::from_path(resource_path);
                let mime = mime::Mime::from_str(guess.first().unwrap().essence_str()).unwrap();
                return Ok(build_raw_response(content.as_bytes().to_vec(), mime));
            } else {
                resource_path = format!("{}/{}/{}", site::SITE_PATH, site.domain, path);
                for part in resource_path.split('/').collect::<Vec<_>>() {
                    let first_char = part.chars().next().unwrap();
                    if first_char == '_' || (first_char == '.' && part.len() > 1) {
                        return Err(tide::Error::from_str(StatusCode::NotFound, ""));
                    }
                }
                if Path::new(&resource_path).exists() {
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
                        if Path::new(&resource_path).exists() {
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

fn get_nostr_auth_event(request: &Request<State>) -> Result<nostr::Event> {
    let auth_header = request
        .header(tide::http::headers::AUTHORIZATION)
        .context("Missing Authorization header")?;
    let parts = auth_header.as_str().split(' ').collect::<Vec<_>>();
    if parts.len() != 2 {
        bail!("Invalid Authorization header");
    }
    if parts[0].to_lowercase() != "nostr" {
        bail!("Expecting Nostr Authorization");
    }

    Ok(serde_json::from_str(str::from_utf8(
        &BASE64.decode(parts[1])?,
    )?)?)
}

fn get_pubkey(request: &Request<State>) -> Result<String> {
    Ok(request.param("pubkey").unwrap().to_string())
}

fn nostr_auth(request: &Request<State>) -> Result<String> {
    let is_https = request
        .header("X-Forwarded-Proto")
        .map(|h| h.as_str() == "https")
        .unwrap_or(false);
    let mut url = request.url().as_str().to_string();
    if is_https && url.starts_with("http:") {
        url = url.replacen("http:", "https:", 1)
    };
    get_nostr_auth_event(request)?.get_nip98_pubkey(&url, request.method().as_ref())
}

fn blossom_upload_auth(request: &Request<State>) -> Result<String> {
    blossom_auth(request, "upload")
}

fn blossom_delete_auth(request: &Request<State>) -> Result<String> {
    blossom_auth(request, "delete")
}

fn blossom_auth(request: &Request<State>, method: &str) -> Result<String> {
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
        match nostr_auth(&request) {
            Err(e) => {
                log::warn!("Nostr auth: {}", e);
                Err(tide::Error::from_str(StatusCode::Unauthorized, ""))
            }
            Ok(key) => match site::create_site(&state.root_path, &domain, Some(key)) {
                Err(e) => {
                    log::warn!("Error creating site {}: {}", &domain, e);
                    Err(tide::Error::new(StatusCode::InternalServerError, e))
                }
                Ok(site) => {
                    let sites = &mut state.sites.write().unwrap();
                    sites.insert(domain, site);

                    Ok(Response::builder(StatusCode::Ok)
                        .content_type(mime::JSON)
                        .header("Access-Control-Allow-Origin", "*")
                        .body(json!({}).to_string())
                        .build())
                }
            },
        }
    }
}

async fn handle_get_sites(request: Request<State>) -> tide::Result<Response> {
    match nostr_auth(&request) {
        Err(e) => {
            log::warn!("Nostr auth: {}", e);
            Err(tide::Error::from_str(StatusCode::Unauthorized, ""))
        }
        Ok(key) => {
            let all_sites = &request.state().sites.read().unwrap();
            let sites = all_sites
                .iter()
                .filter_map(|s| match &s.1.config.pubkey {
                    Some(k) => {
                        if k == &key {
                            Some(HashMap::from([("domain", s.0)]))
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();

            Ok(Response::builder(StatusCode::Ok)
                .content_type(mime::JSON)
                .body(json!(sites).to_string())
                .build())
        }
    }
}

async fn handle_get_themes(request: Request<State>) -> tide::Result<Response> {
    let Ok(themes) = request.state().themes.read() else {
        return Err(tide::Error::from_str(StatusCode::InternalServerError, ""));
    };

    Ok(Response::builder(StatusCode::Ok)
            .content_type(mime::JSON)
            .header("Access-Control-Allow-Origin", "*")
            .body(serde_json::to_string(&json!({"themes": themes.values().map(|t| t.config.clone()).collect::<Vec<ThemeConfig>>()}))?)
            .build())
}

async fn handle_get_theme(request: Request<State>) -> tide::Result<Response> {
    let Ok(themes) = request.state().themes.read() else {
        return Err(tide::Error::from_str(StatusCode::InternalServerError, ""));
    };

    let Some(theme) = themes.get(request.param("theme")?) else {
        return Err(tide::Error::from_str(StatusCode::NotFound, ""));
    };

    Ok(Response::builder(StatusCode::Ok)
        .content_type(mime::JSON)
        .header("Access-Control-Allow-Origin", "*")
        .body(serde_json::to_string(
            &json!({"extra_config": theme.extra_config}),
        )?)
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

    let config_path = format!(
        "{}/sites/{}/_config.toml",
        request.state().root_path,
        site.domain
    );
    let mut config = site::load_config(&config_path).unwrap();

    let old_theme = config.theme;

    // NB: we need to load config from the file rather than using the one already loaded,
    // which is already merged with the theme's config! That means... we need to save it first!
    // TODO: How can this be improved?
    config.theme = request.body_json::<PutSiteConfigRequestBody>().await?.theme;
    site::save_config(&config_path, &config);

    let Ok(themes) = request.state().themes.read() else {
        return Err(tide::Error::from_str(
            StatusCode::InternalServerError,
            "cannot access 'themes'",
        ));
    };

    match site::load_site(&request.state().root_path, &site.domain, &themes) {
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
                StatusCode::BadRequest,
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
    get_pubkey: &dyn Fn(&Request<State>) -> Result<String>,
) -> bool {
    if let Ok(pubkey) = get_pubkey(&request) {
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

async fn server(
    root_path: &str,
    themes: Arc<RwLock<HashMap<String, Theme>>>,
    sites: Arc<RwLock<HashMap<String, Site>>>,
) -> Server<State> {
    let mut app = tide::with_state(State {
        root_path: root_path.to_string(),
        themes,
        sites,
    });

    app.with(log::LogMiddleware::new());
    app.at("/")
        .with(WebSocket::new(handle_websocket))
        .get(handle_index::<Section<PostSectionFilter>>);
    app.at("/posts")
        .get(handle_index::<Section<PostSectionFilter>>);
    app.at("/notes")
        .get(handle_index::<Section<NoteSectionFilter>>);
    app.at("/pictures")
        .get(handle_index::<Section<PictureSectionFilter>>);
    app.at("/listings")
        .get(handle_index::<Section<ListingSectionFilter>>);
    app.at("*path").options(handle_request).get(handle_request);

    // API
    app.at("/api/sites")
        .post(handle_post_site)
        .get(handle_get_sites);

    // Theme API
    app.at("/api/themes").get(handle_get_themes);
    app.at("/api/themes/:theme").get(handle_get_theme);

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

    app
}

fn load_or_download_themes(root_path: &str, url: &str, validate: bool) -> HashMap<String, Theme> {
    let mut themes = theme::load_themes(root_path);

    if themes.len() == 0 {
        log::error!("No themes found!");

        let stdin = io::stdin();
        let mut response = String::new();
        while response != "n" && response != "y" {
            print!("Fetch themes from {}? [y/n]? ", url);
            io::stdout().flush().unwrap();
            response = stdin.lock().lines().next().unwrap().unwrap().to_lowercase();
        }

        if response == "y" {
            if let Err(e) = download_themes(root_path, url, validate) {
                panic!("Failed to fetch themes: {}", e);
            }

            if !validate {
                themes = theme::load_themes(root_path);
            }
        }
    }

    themes
}

fn download_themes(root_path: &str, url: &str, validate: bool) -> Result<()> {
    let themes_dir = &Path::new(root_path).join("themes");
    let mut tempfile = tempfile::tempfile()?;
    let mut response = get(url)?;
    log::info!(
        "Downloading {} bytes from {}...",
        response.content_length().unwrap_or(0),
        url,
    );
    response
        .copy_to(&mut tempfile)
        .context("Error downloading file")?;
    let mut zip = ZipArchive::new(tempfile).context("Error opening archive")?;
    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        if !file.is_dir() {
            let path = match file.enclosed_name() {
                Some(path) => path.to_owned(),
                None => continue,
            };
            log::info!("Extracting {}...", path.to_str().unwrap());
            let output_path = themes_dir.join(path);
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut outfile = File::create(&output_path)?;
            io::copy(&mut file, &mut outfile)?;
        }
    }

    if validate {
        log::info!("Validating themes...");

        let valid_themes_filename = "valid_themes.txt";
        let mut valid_themes_file = File::create(Path::new(root_path).join(valid_themes_filename))?;

        for path in &match fs::read_dir(themes_dir) {
            Ok(paths) => paths.map(|r| r.unwrap()).collect(),
            _ => vec![],
        } {
            let theme = path.file_name();
            let theme = theme.to_str().unwrap();
            if !path.file_type().unwrap().is_dir() || theme.starts_with(".") {
                continue;
            }

            let mut empty_site = Site::empty(&theme);
            let templates = site::load_templates(root_path, &empty_site.config);
            if let Err(e) = templates {
                log::warn!("Failed to load theme templates {}: {}", theme, e);
                continue;
            }
            empty_site.tera = Arc::new(RwLock::new(templates.unwrap()));
            if let Err(e) = render_and_build_response(
                &empty_site,
                Section::<PostSectionFilter>::from_resource(
                    &get_default_index("index"),
                    &empty_site,
                ),
            ) {
                log::warn!("Failed to render theme {}: {}", theme, e);
                continue;
            }

            writeln!(valid_themes_file, "{}", theme).unwrap();
        }

        log::info!("Valid themes saved to {}", valid_themes_filename);
    }

    Ok(())
}

fn load_or_create_sites(root_path: &str, themes: &HashMap<String, Theme>) -> HashMap<String, Site> {
    let existing_sites = site::load_sites(root_path, themes);

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
            let site = site::create_site(root_path, &domain, Some(admin_pubkey)).unwrap();

            [(domain, site)].iter().cloned().collect()
        } else {
            HashMap::new()
        }
    } else {
        existing_sites
    }
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    const DEFAULT_ADDR: &str = "0.0.0.0";
    const DEFAULT_PORT: u32 = 4884;
    const DEFAULT_ROOT_PATH: &str = "./";

    let args = Cli::parse();

    femme::with_level(log::LevelFilter::Info);

    let cache_path = "./cache";

    let themes = load_or_download_themes(
        &DEFAULT_ROOT_PATH,
        &args.themes_url.unwrap_or(DEFAULT_THEMES_URL.to_string()),
        args.validate_themes,
    );

    if args.validate_themes {
        return Ok(());
    }

    if themes.len() == 0 {
        panic!("No themes!");
    }

    let sites = load_or_create_sites(&DEFAULT_ROOT_PATH, &themes);
    let site_count = sites.len();

    let app = server(
        &DEFAULT_ROOT_PATH,
        Arc::new(RwLock::new(themes)),
        Arc::new(RwLock::new(sites)),
    )
    .await;

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
        let cache = DirCache::new(cache_path);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ::nostr::event::{EventId, TagKind};
    use ::nostr::prelude::{ClientMessage, Event, EventBuilder, JsonUtil, Keys, RelayMessage, Tag};
    use ::nostr::{Filter, SubscriptionId};
    use async_std::net::TcpStream;
    use async_std::{
        future::timeout,
        task::{sleep, spawn},
        test,
    };
    use async_tungstenite::async_std::connect_async;
    use async_tungstenite::tungstenite::protocol::Message;
    use async_tungstenite::WebSocketStream;
    use ctor::ctor;
    use futures_util::StreamExt;
    use serde_json::json;
    use std::time::Duration;
    use tempdir::TempDir;
    use tide::http::{Method, Request, Response, Url};

    const TEST_ROOT_DIR_PREFIX: &str = "servus-test";
    const BIND_ADDR: &str = "127.0.0.1:8000";

    // https://github.com/nostr-protocol/nips/blob/master/06.mds
    const LEADER_MONKEY_PRIVATE_KEY: &str =
        "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
    const WHAT_BLEAK_PRIVATE_KEY: &str =
        "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";

    fn with_nostr_auth_header(mut request: Request, sk: &str) -> Request {
        request.append_header(
            "Authorization",
            format!(
                "Nostr {}",
                BASE64.encode(
                    nostr::BareEvent::new(
                        nostr::EVENT_KIND_AUTH,
                        vec![
                            vec!["u".to_string(), request.url().to_string()],
                            vec!["method".to_string(), request.method().to_string()]
                        ],
                        ""
                    )
                    .sign(sk)
                    .to_json_string()
                )
            ),
        );
        request
    }

    fn download_test_themes(root_path: &str) -> Result<()> {
        download_themes(
            &root_path,
            "https://github.com/servus-social/themes/releases/latest/download/test-themes.zip",
            false,
        )?;

        Ok(())
    }

    #[ctor]
    fn setup() {
        femme::with_level(log::LevelFilter::Info);
    }

    #[test]
    async fn test_theme() -> tide::Result<()> {
        let tmp_dir = TempDir::new(TEST_ROOT_DIR_PREFIX)?;
        let root_path = tmp_dir.path().to_str().unwrap();

        download_test_themes(root_path)?;

        let empty_site = Site::empty(&"hyde");

        site::load_templates(root_path, &empty_site.config)?;

        Ok(())
    }

    #[test]
    async fn test_theme_api() -> tide::Result<()> {
        let tmp_dir = TempDir::new(TEST_ROOT_DIR_PREFIX)?;
        let root_path = tmp_dir.path().to_str().unwrap();

        download_test_themes(root_path)?;

        let app = server(
            root_path,
            Arc::new(RwLock::new(theme::load_themes(root_path))),
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        let req = Request::new(Method::Get, Url::parse("https://example.com/api/themes")?);
        let mut res: Response = app.respond(req).await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let body_json: serde_json::Value = res.body_json().await?;

        let Some(themes) = body_json.get("themes") else {
            panic!("Response does not contain 'themes'");
        };
        let Some(themes) = themes.as_array() else {
            panic!("'themes' field is not an array");
        };

        assert_eq!(themes.len(), 2);

        let mut theme_names = Vec::new();
        for theme in themes {
            if let Some(theme) = theme.as_object() {
                if let Some(theme) = theme.get("name") {
                    theme_names.push(theme.as_str().unwrap_or(""));
                }
            }
        }

        assert!(theme_names.contains(&"hyde"));
        assert!(theme_names.contains(&"pico"));

        for theme in theme_names {
            let req = Request::new(
                Method::Get,
                Url::parse(&format!("https://example.com/api/themes/{}", theme))?,
            );
            let mut res: Response = app.respond(req).await?;
            assert_eq!(res.status(), StatusCode::Ok);
            let body_json: serde_json::Value = res.body_json().await?;
            assert!(body_json.get("extra_config").is_some());

            if theme == "hyde" {
                let Some(extra_config) = body_json.get("extra_config") else {
                    panic!("Response body does not contain 'extra_config'");
                };

                let Some(extra_config) = extra_config.as_str() else {
                    panic!("'extra_config' is not a string");
                };

                assert!(extra_config.contains("hyde_links"));
            }

            // add an "a" after the theme name
            let req = Request::new(
                Method::Get,
                Url::parse(&format!("https://example.com/api/themes/{}a", theme))?,
            );
            let res: Response = app.respond(req).await?;
            assert_eq!(res.status(), StatusCode::NotFound);
        }

        Ok(())
    }

    #[test]
    async fn test_sites_api() -> tide::Result<()> {
        let tmp_dir = TempDir::new(TEST_ROOT_DIR_PREFIX)?;
        let root_path = tmp_dir.path().to_str().unwrap();

        let api_url = Url::parse("https://example.com/api/sites")?;

        download_test_themes(root_path)?;

        let app = server(
            root_path,
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        // No auth header passed
        let req = Request::new(Method::Get, api_url.clone());
        let res: Response = app.respond(req).await?;
        assert_eq!(res.status(), StatusCode::Unauthorized);

        // We don't have any sites
        let req = with_nostr_auth_header(
            Request::new(Method::Get, api_url.clone()),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        let mut res: Response = app.respond(req).await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let body_json: serde_json::Value = res.body_json().await?;
        assert_eq!(body_json, json!([]));

        // Let's create a site!
        let mut req = with_nostr_auth_header(
            Request::new(Method::Post, api_url.clone()),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(serde_json::to_string(&json!({"domain": "site1.com"}))?);
        let mut res: Response = app.respond(req).await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let body_json: serde_json::Value = res.body_json().await?;
        assert_eq!(body_json, json!({}));

        // We can see the site...
        let req = with_nostr_auth_header(
            Request::new(Method::Get, api_url.clone()),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        let mut res: Response = app.respond(req).await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let body_json: serde_json::Value = res.body_json().await?;
        assert_eq!(body_json, json!([{"domain": "site1.com"}]));

        // ...but somebody else can't see it
        let req = with_nostr_auth_header(
            Request::new(Method::Get, api_url.clone()),
            WHAT_BLEAK_PRIVATE_KEY,
        );
        let mut res: Response = app.respond(req).await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let body_json: serde_json::Value = res.body_json().await?;
        assert_eq!(body_json, json!([]));

        Ok(())
    }

    #[test]
    async fn test_config_api() -> tide::Result<()> {
        let tmp_dir = TempDir::new(TEST_ROOT_DIR_PREFIX)?;
        let root_path = tmp_dir.path().to_str().unwrap();

        let sites_api_url = Url::parse("https://example.com/api/sites")?;
        let api_url = Url::parse("https://site1.com/api/config")?;

        download_test_themes(root_path)?;

        let app = server(
            root_path,
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        // Create the site
        let mut req = with_nostr_auth_header(
            Request::new(Method::Post, sites_api_url.clone()),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(serde_json::to_string(&json!({"domain": "site1.com"}))?);
        let _: Response = app.respond(req).await?;

        // Create another site
        let mut req = with_nostr_auth_header(
            Request::new(Method::Post, sites_api_url.clone()),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(serde_json::to_string(&json!({"domain": "site2.com"}))?);
        let _: Response = app.respond(req).await?;

        // Get an inexistant site's config
        let req = with_nostr_auth_header(
            Request::new(Method::Get, Url::parse("https://site3.com/api/config")?),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        let res: Response = app.respond(req).await?;
        assert_eq!(res.status(), StatusCode::NotFound);

        // Get the site's config
        let req = with_nostr_auth_header(
            Request::new(Method::Get, api_url.clone()),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        let mut res: Response = app.respond(req).await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let body_json: serde_json::Value = res.body_json().await?;
        assert_eq!(body_json, json!({"theme": "hyde", "available_themes": []}));

        // Change the theme to an inexistant one
        let mut req = with_nostr_auth_header(
            Request::new(Method::Put, api_url.clone()),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(serde_json::to_string(&json!({"theme": "inexistant"}))?);
        let res: Response = app.respond(req).await?;
        assert_eq!(res.status(), StatusCode::BadRequest);

        // Change the theme to a valid one
        let mut req = with_nostr_auth_header(
            Request::new(Method::Put, api_url.clone()),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(serde_json::to_string(&json!({"theme": "pico"}))?);
        let res: Response = app.respond(req).await?;
        assert_eq!(res.status(), StatusCode::Ok);

        Ok(())
    }

    async fn read_relay_message(
        ws_stream: &mut WebSocketStream<TcpStream>,
    ) -> Result<RelayMessage> {
        if let Some(msg) = timeout(Duration::from_secs(1), ws_stream.next()).await? {
            match msg? {
                Message::Text(response) => {
                    return Ok(RelayMessage::from_value(serde_json::from_str(&response)?)?);
                }
                _ => bail!("Expected text message"),
            }
        } else {
            bail!("Expected WebSocket message");
        }
    }

    async fn read_ok(
        ws_stream: &mut WebSocketStream<TcpStream>,
        expected_event_id: EventId,
    ) -> Result<()> {
        match read_relay_message(ws_stream).await? {
            RelayMessage::Ok { event_id, .. } => {
                assert_eq!(event_id, expected_event_id);
            }
            _ => {
                bail!("Unexpected message received");
            }
        };

        Ok(())
    }

    async fn send_client_message(
        ws_stream: &mut WebSocketStream<TcpStream>,
        message: ClientMessage,
    ) -> Result<()> {
        ws_stream
            .send(Message::Text(message.as_json().into()))
            .await?;
        Ok(())
    }

    async fn query_relay(
        ws_stream: &mut WebSocketStream<TcpStream>,
        filter: Filter,
    ) -> Result<Vec<Box<Event>>> {
        let mut ret = Vec::new();

        send_client_message(
            ws_stream,
            ClientMessage::req(SubscriptionId::generate(), filter),
        )
        .await?;

        loop {
            match read_relay_message(ws_stream).await? {
                RelayMessage::Event { event, .. } => {
                    if !event.verify_signature() {
                        bail!("Invalid signature");
                    }
                    ret.push(event);
                }
                RelayMessage::EndOfStoredEvents(_) => {
                    break;
                }
                _ => {
                    bail!("Unexpected message");
                }
            }
        }

        Ok(ret)
    }

    #[test]
    async fn test_nostr_relay() -> Result<()> {
        let tmp_dir = TempDir::new(TEST_ROOT_DIR_PREFIX)?;
        let root_path = tmp_dir.path().to_str().unwrap();
        let keys = Keys::generate();
        let site = Site::empty(&"hyde").with_pubkey(keys.public_key.to_hex());

        let app = server(
            root_path,
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(HashMap::from([("test.com".to_string(), site)]))),
        )
        .await;

        let _server_task = spawn(async { app.listen(BIND_ADDR).await });
        sleep(std::time::Duration::from_secs(1)).await;

        let (mut ws_stream, _) = connect_async(format!("ws://{}/", BIND_ADDR)).await?;

        for i in 1..=10 {
            let post_content = format!("Hello post {} from rust-nostr!", i);
            let post = EventBuilder::long_form_text_note(post_content)
                .tag(Tag::identifier(format!("post-{}", i)))
                .sign_with_keys(&keys)?;

            let page_content = format!("Hello post {} from rust-nostr!", i);
            let page = EventBuilder::long_form_text_note(page_content)
                .tag(Tag::hashtag("page"))
                .tag(Tag::identifier(format!("page-{}", i)))
                .sign_with_keys(&keys)?;

            let note_content = format!("Hello note {} from rust-nostr!", i);
            let note = EventBuilder::text_note(note_content).sign_with_keys(&keys)?;

            for event in &[post, page, note] {
                send_client_message(&mut ws_stream, ClientMessage::event(event.clone())).await?;

                read_ok(&mut ws_stream, event.id).await?;

                let received_events =
                    query_relay(&mut ws_stream, Filter::new().id(event.id)).await?;

                assert_eq!(received_events.len(), 1);
                assert_eq!(received_events[0].id, event.id);
                assert_eq!(received_events[0].content, event.content);
            }
        }

        let all_events = query_relay(&mut ws_stream, Filter::new()).await?;

        assert_eq!(all_events.len(), 30);

        let edited_post_content = format!("Hello edited post 5 from rust-nostr!");
        let edited_post = EventBuilder::long_form_text_note(edited_post_content.clone())
            .tag(Tag::identifier(format!("post-5")))
            .sign_with_keys(&keys)?;

        send_client_message(&mut ws_stream, ClientMessage::event(edited_post.clone())).await?;

        read_ok(&mut ws_stream, edited_post.id).await?;

        let all_events_after_edit = query_relay(&mut ws_stream, Filter::new()).await?;

        assert_eq!(all_events_after_edit.len(), 30);

        let mut edited_event_id: Option<EventId> = None;
        for e in all_events_after_edit {
            for t in e.tags {
                if t.kind() == TagKind::d() && t.content() == Some("post-5") {
                    assert_eq!(e.content, edited_post_content);
                    edited_event_id = Some(e.id);
                }
            }
        }
        assert_eq!(edited_event_id.is_some(), true);

        let delete = EventBuilder::delete(vec![edited_event_id.unwrap()]).sign_with_keys(&keys)?;
        send_client_message(&mut ws_stream, ClientMessage::event(delete.clone())).await?;

        read_ok(&mut ws_stream, delete.id).await?;

        let all_events_after_delete = query_relay(&mut ws_stream, Filter::new()).await?;

        assert_eq!(all_events_after_delete.len(), 29);

        Ok(())
    }
}
