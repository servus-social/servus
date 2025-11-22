use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use clap::Parser;
use http_types::{mime, Method};
use phf::phf_set;
use reqwest::blocking::get;
use secp256k1::{rand, KeyPair, Secp256k1};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
mod ig;
mod nostr;
mod resource;
mod sass;
mod site;
mod template;
mod theme;
mod twitter;

use resource::{
    ListingSectionFilter, NoteSectionFilter, Page, PictureSectionFilter, PostSectionFilter,
    Renderable, Resource, ResourceKind, Section,
};
use site::Site;
use theme::{Theme, ThemeConfig};

const ALL_THEMES_URL: &str =
    "https://github.com/servus-social/themes/releases/latest/download/all-themes.zip";
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

    #[clap(short('a'), long)]
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

    #[clap(short('s'), long)]
    sign_content: bool,
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
    extra_config: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct ThemeMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub license: Option<String>,
}

impl ThemeMetadata {
    fn from_config_with_id(c: ThemeConfig, id: String) -> Self {
        ThemeMetadata {
            id,
            name: c.name,
            description: c.description,
            license: c.license,
        }
    }
}

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

impl FileMetadata {
    pub fn read(root_path: &str, site_domain: &str, sha256: &str) -> Self {
        let metadata_file = File::open(&format!(
            "{}/sites/{}/_content/files/{}.metadata.json",
            root_path, site_domain, sha256
        ))
        .unwrap();
        let metadata_reader = BufReader::new(metadata_file);
        serde_json::from_reader(metadata_reader).unwrap()
    }
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
        let Ok(nostr_message) = nostr::Message::from_str(&message) else {
            log::warn!("Cannot parse: {}", message);
            continue;
        };
        match nostr_message {
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
                        let post_removed =
                            site.remove_content(&request.state().root_path, &event)?;
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
                        .await?;
                    } else {
                        site.add_content(&request.state().root_path, &event)?;
                        log::info!("Incoming event: {}.", event.id);
                        ws.send_json(&json!(vec![
                            serde_json::Value::String("OK".to_string()),
                            serde_json::Value::String(event.id.to_string()),
                            serde_json::Value::Bool(true),
                            serde_json::Value::String("".to_string())
                        ]))
                        .await?;
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
                            for event in site.events.read().unwrap().values() {
                                if filter.matches_kind(&event.kind)
                                    && filter.matches_time(&event.created_at)
                                {
                                    if filter.matches_id(&event.id)
                                        && filter.matches_author(&event.pubkey)
                                    {
                                        events.push(event.clone());
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
                    .await?;
                }
                ws.send_json(&json!(vec!["EOSE", &sub_id.to_string()]))
                    .await?;
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

fn get_default_index(slug: &str) -> Resource {
    Resource {
        kind: ResourceKind::Page,
        slug: slug.to_string(),
        date: Utc::now().naive_utc(),
        event_id: None,
    }
}

fn get_site(request: &Request<State>) -> Option<Site> {
    let mut host = request.host();

    let sites = request.state().sites.read().unwrap();

    if let Some(host) = host {
        if host.starts_with("localhost:") || host.starts_with("127.0.0.1:") {
            // When hitting the server via localhost
            // we expect the query string to contain the domain
            // (http://localhost:port/?example.com)
            // so that we can know which of the existing sites the request is referring to.
            // This is not a problem in a production environment
            // where the site's domain must be the request's host
            // (http://example.com).
            // This extra query parameter is added in SiteConfig::make_permalink,
            // which is why we are using a modified SiteConfig here.
            if let Some(query) = request.url().query() {
                if let Some(mut site) = sites.get(query).cloned() {
                    site.config.base_url = format!("http://{host}").to_string();
                    site.tera
                        .write()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .register_function(
                            "get_url",
                            template::GetUrl::new(request.state().root_path.clone(), site.clone()),
                        );
                    site.tera
                        .write()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .register_function(
                            "resize_image",
                            template::ResizeImage::new(
                                request.state().root_path.clone(),
                                site.clone(),
                            ),
                        );
                    return Some(site);
                }
            }
        }
    }

    // For API calls, we use the X-Target-Host header rather than the "?domain" trick used above.
    // NB: we use the X-Target-Host rather than the Host header
    // because client-side code cannot freely set the Host header!
    if let Some(target_host) = request.header("X-Target-Host").map(|h| h.as_str()) {
        host = Some(target_host);
    }

    if let Some(host) = host {
        sites.get(host).map(|s| s.clone())
    } else {
        None
    }
}

async fn handle_request(request: Request<State>) -> tide::Result<Response> {
    let mut path = request.param("path").unwrap_or("/");
    if path.ends_with('/') {
        path = path.strip_suffix('/').unwrap();
    }

    if path.starts_with(".admin") {
        let admin_index = if path.starts_with(".admin/") {
            // /.admin/domain
            let administered_host = &path[7..];
            admin::INDEX_HTML.replace("%%ADMINISTERED_HOST%%", administered_host)
        } else {
            // /.admin home
            admin::INDEX_HTML.replace("%%ADMINISTERED_HOST%%", "")
        }
        .replace(
            "%%API_BASE_URL%%",
            &format!("//{}", request.host().unwrap()),
        );
        return Ok(Response::builder(StatusCode::Ok)
            .content_type(mime::HTML)
            .body(admin_index)
            .build());
    }

    let mut part: Option<String> = None;
    if path.contains(".") {
        let path = if path.contains("/") {
            path.split("/").collect::<Vec<_>>().last().unwrap()
        } else {
            path
        };
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
        if let Some((mime, response)) = resource::render_standard_resource(path, &site)? {
            return Ok(Response::builder(StatusCode::Ok)
                .content_type(mime)
                .header("Access-Control-Allow-Origin", "*")
                .body(response)
                .build());
        }

        let mut resource_path = format!("/{}", &path);

        let mut page: Option<Page> = None;
        let mut posts_section: Option<Section<PostSectionFilter>> = None;
        let mut notes_section: Option<Section<NoteSectionFilter>> = None;
        let mut pictures_section: Option<Section<PictureSectionFilter>> = None;
        let mut listings_section: Option<Section<ListingSectionFilter>> = None;
        {
            let resources = site.resources.read().unwrap();
            if let Some(r) = resources.get(&resource_path) {
                page = Some(Page::from_resource(r, &site)?);
            } else {
                let mut slug = request.url().path_segments().unwrap().last().unwrap();
                if slug == "" {
                    slug = "index";
                }
                let default_index = get_default_index(&slug);
                let r = resources
                    .get(&format!("/{}", &slug))
                    .unwrap_or(&default_index);
                if resource_path == "/" {
                    posts_section = Some(Section::from_resource(r, &site)?);
                }
                if resource_path == "/posts" {
                    posts_section = Some(Section::from_resource(r, &site)?);
                } else if resource_path == "/notes" {
                    notes_section = Some(Section::from_resource(r, &site)?);
                } else if resource_path == "/pictures" {
                    pictures_section = Some(Section::from_resource(r, &site)?);
                } else if resource_path == "/listings" {
                    listings_section = Some(Section::from_resource(r, &site)?);
                }
            }
        };

        if let Some(page) = page {
            return render_and_build_response(&site, page);
        } else if let Some(section) = posts_section {
            return render_and_build_response(&site, section);
        } else if let Some(section) = notes_section {
            return render_and_build_response(&site, section);
        } else if let Some(section) = pictures_section {
            return render_and_build_response(&site, section);
        } else if let Some(section) = listings_section {
            return render_and_build_response(&site, section);
        } else {
            let themes = request.state().themes.read().unwrap();
            let mut theme_content = None;
            if let Some(theme) = themes.get(&site.config.theme) {
                let theme_resources = theme.resources.read().unwrap();
                if let Some(content) = theme_resources.get(&resource_path) {
                    theme_content = Some(content.as_bytes().to_vec());
                }
            }
            if let Some(theme_content) = theme_content {
                let guess = mime_guess::from_path(resource_path);
                let mime = mime::Mime::from_str(guess.first().unwrap().essence_str()).unwrap();
                return Ok(build_raw_response(theme_content, mime));
            } else {
                resource_path = format!(
                    "{}/sites/{}/{}",
                    request.state().root_path,
                    site.domain,
                    path
                );
                let static_theme_path = format!(
                    "{}/themes/{}/static/{}",
                    request.state().root_path,
                    &site.config.theme,
                    path
                );
                for part in resource_path.split('/').collect::<Vec<_>>() {
                    if let Some(first_char) = part.chars().next() {
                        if first_char == '_' || (first_char == '.' && part.len() > 1) {
                            return Err(tide::Error::from_str(StatusCode::NotFound, ""));
                        }
                    }
                }
                if Path::new(&resource_path).exists() {
                    // look for a static file
                    let raw_content = fs::read(&resource_path).unwrap();
                    let guess = mime_guess::from_path(resource_path);
                    let mime = if let Some(sha256) = sha256 {
                        let metadata =
                            FileMetadata::read(&request.state().root_path, &site.domain, &sha256);
                        mime::Mime::from_str(&metadata.content_type).unwrap()
                    } else {
                        mime::Mime::from_str(guess.first().unwrap().essence_str()).unwrap()
                    };
                    return Ok(build_raw_response(raw_content, mime));
                } else if Path::new(&static_theme_path).exists() {
                    let raw_content = fs::read(&static_theme_path).unwrap();
                    let guess = mime_guess::from_path(resource_path);
                    let mime = mime::Mime::from_str(guess.first().unwrap().essence_str()).unwrap();
                    return Ok(build_raw_response(raw_content, mime));
                } else {
                    // look for an uploaded file
                    if let Some(sha256) = sha256 {
                        resource_path = format!(
                            "{}/sites/{}/_content/files/{}",
                            request.state().root_path,
                            site.domain,
                            sha256
                        );
                        if Path::new(&resource_path).exists() {
                            let raw_content = fs::read(&resource_path).unwrap();
                            let metadata = FileMetadata::read(
                                &request.state().root_path,
                                &site.domain,
                                &sha256,
                            );
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

fn blossom_auth(request: &Request<State>, method: &str, hash: &str) -> Result<String> {
    get_nostr_auth_event(request)?.get_blossom_pubkey(method, hash)
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
        let Ok(themes) = request.state().themes.read() else {
            return Err(tide::Error::from_str(
                StatusCode::InternalServerError,
                "Cannot access themes",
            ));
        };
        match nostr_auth(&request) {
            Err(e) => {
                log::warn!("Nostr auth: {}", e);
                Err(tide::Error::from_str(StatusCode::Unauthorized, ""))
            }
            Ok(key) => {
                match site::create_site(&state.root_path, &domain, Some(key), &*themes, None) {
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
                }
            }
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

    let themes = themes
        .iter()
        .map(|(k, t)| ThemeMetadata::from_config_with_id(t.config.clone(), k.to_string()))
        .collect::<Vec<ThemeMetadata>>();

    Ok(Response::builder(StatusCode::Ok)
        .content_type(mime::JSON)
        .header("Access-Control-Allow-Origin", "*")
        .body(serde_json::to_string(&json!({"themes": themes}))?)
        .build())
}

async fn handle_get_theme(request: Request<State>) -> tide::Result<Response> {
    let theme_id = request.param("theme")?;
    let site_extra_config = if let Some(site) = get_site(&request) {
        let pubkey = nostr_auth(&request);
        if let Some(r) = get_unauthorized_response(&site, pubkey).await {
            return Ok(r);
        }
        let extra_config_filename = format!(
            "{}/sites/{}/_config.{}.toml",
            request.state().root_path,
            site.domain,
            &theme_id,
        );
        if let Ok(c) = fs::read(&extra_config_filename) {
            Some(String::from_utf8(c).unwrap())
        } else {
            None
        }
    } else {
        None
    };

    let Ok(themes) = request.state().themes.read() else {
        return Err(tide::Error::from_str(StatusCode::InternalServerError, ""));
    };

    let Some(theme) = themes.get(theme_id) else {
        return Err(tide::Error::from_str(StatusCode::NotFound, ""));
    };

    Ok(Response::builder(StatusCode::Ok)
        .content_type(mime::JSON)
        .header("Access-Control-Allow-Origin", "*")
        .body(serde_json::to_string(
            &json!({"extra_config": site_extra_config.unwrap_or(theme.extra_config.clone())}),
        )?)
        .build())
}

async fn handle_get_site_config(request: Request<State>) -> tide::Result<Response> {
    let site = {
        if let Some(site) = get_site(&request) {
            let pubkey = nostr_auth(&request);
            if let Some(r) = get_unauthorized_response(&site, pubkey).await {
                return Ok(r);
            }
            site
        } else {
            return Err(tide::Error::from_str(StatusCode::NotFound, ""));
        }
    };

    Ok(Response::builder(StatusCode::Ok)
        .content_type(mime::JSON)
        .body(json!({"theme": site.config.theme}).to_string())
        .build())
}

async fn handle_put_site_config(mut request: Request<State>) -> tide::Result<Response> {
    let site = {
        if let Some(site) = get_site(&request) {
            let pubkey = nostr_auth(&request);
            if let Some(r) = get_unauthorized_response(&site, pubkey).await {
                return Ok(r);
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
    let mut config = site::load_config(&config_path)?;

    let old_theme = config.theme;

    let body: PutSiteConfigRequestBody = request.body_json().await?;

    config.theme = body.theme;

    if let Some(extra_config) = body.extra_config {
        match toml::from_str(&extra_config) {
            Ok(parsed_extra_config) => {
                if fs::write(
                    format!(
                        "{}/sites/{}/_config.{}.toml",
                        request.state().root_path,
                        site.domain,
                        &config.theme,
                    ),
                    extra_config,
                )
                .is_err()
                {
                    return Err(tide::Error::from_str(
                        StatusCode::InternalServerError,
                        "Cannot write theme config",
                    ));
                }
                config = config.with_extra(parsed_extra_config, true);
            }
            Err(_) => {
                return Err(tide::Error::from_str(
                    StatusCode::BadRequest,
                    "Cannot parse theme config",
                ));
            }
        };
    }

    // NB: we need to load config from the file rather than using the one already loaded,
    // which is already merged with the theme's config! That means... we need to save it first!
    // TODO: How can this be improved?
    site::save_config(&config_path, &config)?;

    let Ok(themes) = request.state().themes.read() else {
        return Err(tide::Error::from_str(
            StatusCode::InternalServerError,
            "Cannot access themes",
        ));
    };

    match site::load_site(&request.state().root_path, &site.domain, &themes, &None) {
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
            site::save_config(&config_path, &config)?;
            Err(tide::Error::from_str(
                StatusCode::BadRequest,
                "Failed to change theme!",
            ))
        }
    }
}

async fn handle_blossom_list_request(request: Request<State>) -> tide::Result<Response> {
    if request.method() == Method::Options {
        return Ok(Response::builder(StatusCode::Ok)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Authorization,*")
            .header("Access-Control-Allow-Methods", "GET")
            .build());
    }

    let Some(site) = get_site(&request) else {
        return Err(tide::Error::from_str(StatusCode::NotFound, ""));
    };

    if let Some(r) = get_unauthorized_response(&site, get_pubkey(&request)).await {
        return Ok(r);
    }

    let site_path = format!("{}/sites/{}", request.state().root_path, site.domain);

    let paths = match fs::read_dir(format!("{}/_content/files", site_path)) {
        Ok(paths) => paths.filter_map(Result::ok).collect(),
        _ => vec![],
    };

    let mut list = vec![];
    for path in &paths {
        if path.path().extension().is_none() {
            let metadata = FileMetadata::read(
                &request.state().root_path,
                &site.domain,
                path.path().file_stem().unwrap().to_str().unwrap(),
            );
            list.push(metadata);
        }
    }

    return Ok(Response::builder(StatusCode::Ok)
        .content_type(mime::JSON)
        .header("Access-Control-Allow-Origin", "*")
        .body(serde_json::to_string(&list).unwrap())
        .build());
}

async fn is_authorized(site: &Site, pubkey: Result<String>) -> Result<bool> {
    match pubkey {
        Ok(pubkey) => {
            if let Some(site_pubkey) = site.config.pubkey.to_owned() {
                if site_pubkey != pubkey {
                    log::info!("Non-matching key.");
                    return Ok(false);
                }
            } else {
                log::info!("The site has no pubkey.");
                return Ok(false);
            }
        }
        Err(e) => {
            log::info!("Invalid/missing auth header: {:?}.", e);
            bail!(e);
        }
    }

    return Ok(true);
}

async fn get_unauthorized_response(site: &Site, pubkey: Result<String>) -> Option<Response> {
    let is_authorized = is_authorized(site, pubkey).await;
    match is_authorized {
        Err(_) | Ok(false) => {
            let msg = match is_authorized {
                Err(e) => format!("{:?}", e),
                Ok(false) => "Unauthorized".to_string(),
                _ => unreachable!(),
            };
            return Some(
                Response::builder(StatusCode::Unauthorized)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(msg)
                    .build(),
            );
        }
        _ => {}
    }

    None
}

fn write_file<C>(
    site_path: &str,
    host: &str,
    hash: &str,
    mime: &http_types::mime::Mime,
    size: usize,
    content: C,
) -> Result<FileMetadata>
where
    C: AsRef<[u8]>,
{
    let metadata = FileMetadata {
        sha256: hash.to_owned(),
        content_type: mime.essence().to_owned(),
        size,
        url: format!("https://{}/{}", host, hash),
    };

    fs::create_dir_all(format!("{}/_content/files", site_path))?;
    fs::write(format!("{}/_content/files/{}", site_path, hash), content)?;
    fs::write(
        format!("{}/_content/files/{}.metadata.json", site_path, hash),
        serde_json::to_string(&metadata)?,
    )?;

    Ok(metadata)
}

fn delete_file(site_path: &str, hash: &str) -> Result<()> {
    fs::remove_file(format!("{}/_content/files/{}", site_path, hash))?;
    fs::remove_file(format!(
        "{}/_content/files/{}.metadata.json",
        site_path, hash
    ))?;

    Ok(())
}

async fn handle_blossom_upload_request(mut request: Request<State>) -> tide::Result<Response> {
    if request.method() == Method::Options {
        return Ok(Response::builder(StatusCode::Ok)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Authorization,*")
            .header("Access-Control-Allow-Methods", "PUT")
            .build());
    }

    if let Some(site) = get_site(&request) {
        let bytes = request.body_bytes().await?;
        let hash = sha256::digest(&*bytes);

        let pubkey = blossom_auth(&request, "upload", &hash);
        if let Some(r) = get_unauthorized_response(&site, pubkey).await {
            return Ok(r);
        }
        let site_path = format!("{}/sites/{}", request.state().root_path, site.domain);
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
        )?;

        return Ok(Response::builder(StatusCode::Created)
            .content_type(mime::JSON)
            .header("Access-Control-Allow-Origin", "*")
            .body(serde_json::to_string(&metadata).unwrap())
            .build());
    } else {
        return Err(tide::Error::from_str(StatusCode::NotFound, ""));
    }
}

async fn handle_blossom_delete_request(request: Request<State>) -> tide::Result<Response> {
    if let Some(site) = get_site(&request) {
        let sha256 = request.param("sha256")?;
        let pubkey = blossom_auth(&request, "delete", &sha256);
        if let Some(r) = get_unauthorized_response(&site, pubkey).await {
            return Ok(r);
        }
        let site_path = format!("{}/sites/{}", request.state().root_path, site.domain);

        delete_file(&site_path, sha256)?;

        return Ok(Response::builder(StatusCode::Ok)
            .content_type(mime::JSON)
            .header("Access-Control-Allow-Origin", "*")
            .body(json!({}))
            .build());
    } else {
        return Err(tide::Error::from_str(StatusCode::NotFound, ""));
    }
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
        .get(handle_request);
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
    app.at("/list/:pubkey")
        .options(handle_blossom_list_request)
        .get(handle_blossom_list_request);
    app.at("/:sha256").delete(handle_blossom_delete_request);

    app
}

fn load_or_download_themes(root_path: &str, url: &str) -> HashMap<String, Theme> {
    let mut themes = theme::load_themes(root_path);

    if themes.len() == 0 {
        log::error!("No themes found!");

        let stdin = io::stdin();
        let mut response = String::new();
        while response != "n" && response != "y" && response != "a" {
            print!(
                "Fetch themes?\n[Y]es fetch {}\n[A]ll fetch {}\n[N]o\nYour choice: ",
                url, ALL_THEMES_URL
            );
            io::stdout().flush().unwrap();
            response = stdin.lock().lines().next().unwrap().unwrap().to_lowercase();
        }

        let download_url = if response == "y" {
            Some(url)
        } else if response == "a" {
            Some(ALL_THEMES_URL)
        } else {
            None
        };

        if let Some(download_url) = download_url {
            if let Err(e) = download_themes(root_path, download_url) {
                panic!("Failed to fetch themes: {}", e);
            }

            themes = theme::load_themes(root_path);
        }
    }

    themes
}

fn download_themes(root_path: &str, url: &str) -> Result<()> {
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

    Ok(())
}

fn try_import_ig(root_path: &str, site: &Site, secret_key: &Option<String>) -> Result<bool> {
    loop {
        let mut response = String::new();
        while response != "n" && response != "y" {
            print!("Import Instagram dump? (note: private key required) [y/n]: ");
            io::stdout().flush()?;
            response = io::stdin().lock().lines().next().unwrap()?.to_lowercase();
        }

        if response == "n" {
            return Ok(false);
        } else {
            let Some(secret_key) = secret_key else {
                println!("Start servus with --sign-content and pass a secret key that will be used to sign the events if you want to import your Instagram content!");
                continue;
            };
            print!("Path to .zip file: ");
            io::stdout().flush()?;
            let ig_dump_path = io::stdin().lock().lines().next().unwrap()?;
            let site_path = format!("{}/sites/{}", root_path, site.domain);

            match ig::import_ig(&ig_dump_path) {
                Ok(i) => {
                    for ig_post in i {
                        let ig_post = ig_post?;
                        let hash = sha256::digest(&*ig_post.image_data);
                        let Ok(mime) = mime::Mime::sniff(&ig_post.image_data) else {
                            println!("Cannot sniff mime!");
                            continue;
                        };
                        write_file(
                            &site_path,
                            &site.domain,
                            &hash,
                            &mime,
                            ig_post.image_data.len(),
                            ig_post.image_data,
                        )?;
                        let url_tag = format!("url http://{}/{}", &site.domain, &hash);
                        let x_tag = format!("x {}", &hash);
                        let mut bare_event = nostr::BareEvent::new(
                            nostr::EVENT_KIND_PICTURE,
                            vec![vec!["imeta".to_string(), url_tag, x_tag]],
                            "",
                        );
                        bare_event.created_at = ig_post.date.and_utc().timestamp();
                        site.add_content(root_path, &bare_event.sign(&secret_key))?;
                        println!("Saved post from {}", ig_post.date);
                    }
                    return Ok(true);
                }
                Err(e) => {
                    println!("{}", e);
                }
            }
        }
    }
}

fn try_import_twitter(root_path: &str, site: &Site, secret_key: &Option<String>) -> Result<bool> {
    loop {
        let mut response = String::new();
        while response != "n" && response != "y" {
            print!("Import Twitter dump? (note: private key required) [y/n]: ");
            io::stdout().flush()?;
            response = io::stdin().lock().lines().next().unwrap()?.to_lowercase();
        }

        if response == "n" {
            return Ok(false);
        } else {
            let Some(secret_key) = secret_key else {
                println!("Start servus with --sign-content and pass a secret key that will be used to sign the events if you want to import your Twitter content!");
                continue;
            };
            print!("Path to .zip file: ");
            io::stdout().flush()?;
            let twitter_dump_path = io::stdin().lock().lines().next().unwrap()?;

            match twitter::import_tweets(&twitter_dump_path) {
                Ok(t) => {
                    for tweet in t {
                        let tweet = tweet?;
                        let mut bare_event =
                            nostr::BareEvent::new(nostr::EVENT_KIND_NOTE, vec![], &tweet.full_text);
                        bare_event.created_at = tweet.created_at.and_utc().timestamp();
                        site.add_content(root_path, &bare_event.sign(&secret_key))?;
                        println!("Saved post from {}", tweet.created_at);
                    }
                    return Ok(true);
                }
                Err(e) => {
                    println!("{}", e);
                }
            }
        }
    }
}

fn load_or_create_sites(
    root_path: &str,
    themes: &HashMap<String, Theme>,
    secret_key: &Option<String>,
) -> Result<HashMap<String, Site>> {
    let existing_sites = site::load_sites(root_path, themes, secret_key)?;

    if existing_sites.len() == 0 {
        let stdin = io::stdin();
        let mut response = String::new();
        while response != "n" && response != "y" {
            print!("No sites found. Create a site? [y/n]: ");
            io::stdout().flush()?;
            response = stdin.lock().lines().next().unwrap()?.to_lowercase();
        }

        if response == "y" {
            print!("Domain: ");
            io::stdout().flush()?;
            let domain = stdin.lock().lines().next().unwrap()?.to_lowercase();
            print!("Admin pubkey [generate]: ");
            io::stdout().flush()?;
            response = stdin.lock().lines().next().unwrap()?.to_lowercase();
            let admin_pubkey = if response == "" {
                let secp = Secp256k1::new();
                let keypair = KeyPair::new(&secp, &mut rand::thread_rng());
                println!("PRIVATE KEY: {}", keypair.display_secret());
                keypair.x_only_public_key().0.to_string()
            } else {
                response
            };
            let mut site = site::create_site(root_path, &domain, Some(admin_pubkey), themes, None)?;
            let config_path = format!("{}/sites/{}/_config.toml", root_path, &domain);

            if try_import_ig(root_path, &site, secret_key)? {
                site.config.theme = site::DEFAULT_THEME_PHOTOBLOG.to_string();
                site::save_config(&config_path, &site.config)?;
                site = site::load_site(root_path, &domain, themes, &None)?;
            } else {
                try_import_twitter(root_path, &site, secret_key)?;
            }

            Ok([(domain, site)].iter().cloned().collect())
        } else {
            Ok(HashMap::new())
        }
    } else {
        Ok(existing_sites)
    }
}

fn validate_themes(
    themes: HashMap<String, Theme>,
    root_path: &str,
    valid_themes_filename: &str,
) -> Result<()> {
    let mut valid_themes_file = File::create(Path::new(root_path).join(valid_themes_filename))?;

    for (theme_id, theme) in themes.iter() {
        let mut empty_site = Site::empty(&theme_id);
        match toml::from_str(&theme.extra_config) {
            Ok(extra_config) => {
                empty_site.config = empty_site.config.with_extra(extra_config, false);
            }
            Err(e) => {
                log::warn!("Failed to load theme extra config {}: {}", theme_id, e);
                continue;
            }
        }
        match site::load_templates(root_path, &empty_site, &empty_site.config) {
            Ok(tera) => {
                empty_site.tera = Arc::new(RwLock::new(Some(tera)));
            }
            Err(e) => {
                log::warn!("Failed to load theme templates {}: {}", theme_id, e);
                continue;
            }
        }
        match render_and_build_response(
            &empty_site,
            Section::<PostSectionFilter>::from_resource(&get_default_index("index"), &empty_site)?,
        ) {
            Err(e) => {
                let mut error_str = format!("{}", e);
                if let Some(source) = e.into_inner().source() {
                    error_str = format!("{} Caused by: {}", error_str, source);
                }
                log::warn!("Failed to render theme {}: {}", theme_id, error_str);
                continue;
            }
            _ => {}
        }

        log::info!("Theme OK: {}", theme_id);

        writeln!(valid_themes_file, "{}", theme_id)?;
    }

    Ok(())
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    const DEFAULT_ADDR: &str = "0.0.0.0";
    const DEFAULT_PORT: u32 = 4884;
    const DEFAULT_ROOT_PATH: &str = "./";
    const VALID_THEMES_FILENAME: &str = "valid_themes.txt";

    let args = Cli::parse();

    femme::with_level(log::LevelFilter::Info);

    let mut secret_key: Option<String> = None;
    if args.sign_content {
        let Ok(env_secret_key) = std::env::var("SERVUS_SECRET_KEY") else {
            println!("SERVUS_SECRET_KEY env var is required if --sign-content was passed");
            std::process::exit(1);
        };
        secp256k1::SecretKey::from_str(&env_secret_key).expect("Cannot parse SERVUS_SECRET_KEY");
        secret_key = Some(env_secret_key);
    }

    let cache_path = "./cache";

    let themes = load_or_download_themes(
        &DEFAULT_ROOT_PATH,
        &args.themes_url.unwrap_or(DEFAULT_THEMES_URL.to_string()),
    );

    if args.validate_themes {
        log::info!("Validating themes...");
        validate_themes(themes, DEFAULT_ROOT_PATH, VALID_THEMES_FILENAME)
            .expect("Theme validation failed");
        log::info!("Valid themes saved to {}. Exiting!", VALID_THEMES_FILENAME);
        return Ok(());
    }

    if themes.len() == 0 {
        panic!("No themes!");
    }

    let sites = load_or_create_sites(&DEFAULT_ROOT_PATH, &themes, &secret_key)
        .expect("Failed to load sites");
    let domains: Vec<String> = sites.keys().map(|d| d.clone()).collect();

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
        for domain in domains {
            println!("++++++");
            println!("*** Your site: http://localhost:{port}/?{domain} ***");
            println!("*** Your Nostr identity (NIP-05): http://localhost:{port}/.well-known/nostr.json?{domain} ***");
            println!("++++++");
        }
        println!("*** Admin interface: http://localhost:{port}/.admin/ ***");
        println!("++++++");
        println!("####################################");
        app.listen(bind_to).await?;
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::create_site;
    use ::nostr::event::{EventId, TagKind};
    use ::nostr::prelude::{
        ClientMessage, Event, EventBuilder, JsonUtil, Keys, Kind, RelayMessage, Tag,
    };
    use ::nostr::{Filter, SubscriptionId};
    use anyhow::anyhow;
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
    use surf;
    use tempdir::TempDir;
    use tide::http::{Method, Request, Response, Url};

    #[derive(Deserialize)]
    struct BlossomBlobDescriptor {
        sha256: String,
        r#type: String,
        size: usize,
        url: String,
    }

    const TEST_ROOT_DIR_PREFIX: &str = "servus-test";

    // https://github.com/nostr-protocol/nips/blob/master/06.mds
    const LEADER_MONKEY_PRIVATE_KEY: &str =
        "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
    const WHAT_BLEAK_PRIVATE_KEY: &str =
        "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";

    const ICON_BYTES: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0xF3, 0xFF, 0x61, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x60,
        0x00, 0x02, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00,
        0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    fn get_nostr_auth_header(url: &str, method: &str, sk: &str) -> String {
        format!(
            "Nostr {}",
            BASE64.encode(
                nostr::BareEvent::new(
                    nostr::EVENT_KIND_AUTH,
                    vec![
                        vec!["u".to_string(), url.to_string()],
                        vec!["method".to_string(), method.to_string()]
                    ],
                    ""
                )
                .sign(sk)
                .to_json_string()
            )
        )
    }

    fn get_blossom_auth_header(
        t: Option<&str>,
        x: Option<&str>,
        expiration: Option<i64>,
        sk: &str,
    ) -> String {
        // Note: arguments to this function should be non-optional in a normal context,
        // but here we are using it for testing and we want the ability to test
        // cases where some tags are missing!
        let mut tags = Vec::new();
        if let Some(t) = t {
            tags.push(vec!["t".to_string(), t.to_string()]);
        }
        if let Some(x) = x {
            tags.push(vec!["x".to_string(), x.to_string()]);
        }
        if let Some(expiration) = expiration {
            tags.push(vec!["expiration".to_string(), expiration.to_string()]);
        }
        format!(
            "Nostr {}",
            BASE64.encode(
                nostr::BareEvent::new(nostr::EVENT_KIND_BLOSSOM, tags, "")
                    .sign(sk)
                    .to_json_string()
            )
        )
    }

    fn with_nostr_auth_header(mut request: Request, sk: &str) -> Request {
        request.append_header(
            "Authorization",
            get_nostr_auth_header(
                &request.url().to_string(),
                &request.method().to_string(),
                sk,
            ),
        );
        request
    }

    fn with_blossom_auth_header(
        mut request: Request,
        t: Option<&str>,
        x: Option<&str>,
        expiration: Option<i64>,
        sk: &str,
    ) -> Request {
        request.append_header(
            "Authorization",
            get_blossom_auth_header(t, x, expiration, sk),
        );
        request
    }

    fn download_test_themes(root_path: &str) -> Result<()> {
        download_themes(
            &root_path,
            "https://github.com/servus-social/themes/releases/latest/download/test-themes.zip",
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

        site::load_templates(root_path, &empty_site, &empty_site.config)?;

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
        assert_eq!(body_json, json!({"theme": "hyde"}));

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

    #[test]
    async fn test_blossom_api() -> tide::Result<()> {
        let sk = secp256k1::SecretKey::from_str(LEADER_MONKEY_PRIVATE_KEY).unwrap();
        let keypair = secp256k1::KeyPair::from_secret_key(secp256k1::SECP256K1, &sk);
        let leader_monkey_pubkey =
            hex::encode(keypair.public_key().x_only_public_key().0.serialize());

        let icon_hash = sha256::digest(&*ICON_BYTES);
        let expected_icon_url = format!("https://site1.com/{}", icon_hash);

        let tmp_dir = TempDir::new(TEST_ROOT_DIR_PREFIX)?;
        let root_path = tmp_dir.path().to_str().unwrap();

        download_test_themes(root_path)?;

        let app = server(
            root_path,
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        // Create the site
        let mut req = with_nostr_auth_header(
            Request::new(Method::Post, Url::parse("https://example.com/api/sites")?),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(serde_json::to_string(&json!({"domain": "site1.com"}))?);
        let response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Ok);

        // try to get the file we did not upload
        let req = Request::new(Method::Get, Url::parse(&expected_icon_url)?);
        let response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::NotFound);

        // can't use /upload on a domain with no associated site
        let mut req = with_nostr_auth_header(
            Request::new(Method::Put, Url::parse("https://example.com/upload")?),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(ICON_BYTES);
        let response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::NotFound);

        // /upload without or with invalid "t" tag
        let mut req = with_blossom_auth_header(
            Request::new(Method::Put, Url::parse("https://site1.com/upload")?),
            None,
            Some("a"),
            Some(Utc::now().timestamp() + 10),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(ICON_BYTES);
        let mut response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Unauthorized);
        let response = response.body_string().await?;
        assert!(response.contains("Blossom: Missing 't' tag"));
        let mut req = with_blossom_auth_header(
            Request::new(Method::Put, Url::parse("https://site1.com/upload")?),
            Some("download"),
            Some("a"),
            Some(Utc::now().timestamp() + 10),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(ICON_BYTES);
        let mut response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Unauthorized);
        let response = response.body_string().await?;
        assert!(response.contains("Blossom: Invalid 't' tag"));

        // /upload auth event expired
        let mut req = with_blossom_auth_header(
            Request::new(Method::Put, Url::parse("https://site1.com/upload")?),
            Some("upload"),
            Some("a"),
            Some(Utc::now().timestamp() - 10),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(ICON_BYTES);
        let mut response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Unauthorized);
        let response = response.body_string().await?;
        assert!(response.contains("Blossom: auth event expired"));

        // /upload invalid 'x' tag
        let mut req = with_blossom_auth_header(
            Request::new(Method::Put, Url::parse("https://site1.com/upload")?),
            Some("upload"),
            Some("a"),
            Some(Utc::now().timestamp() + 10),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(ICON_BYTES);
        let mut response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Unauthorized);
        let response = response.body_string().await?;
        assert!(response.contains("Blossom: Invalid 'x' tag"));

        // /list
        let req = Request::new(
            Method::Get,
            Url::parse(&format!("https://site1.com/list/{}", leader_monkey_pubkey))?,
        );
        let mut response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Ok);
        let response_json: Vec<BlossomBlobDescriptor> = response.body_json().await?;
        assert_eq!(response_json.len(), 0);

        // /upload OK
        let mut req = with_blossom_auth_header(
            Request::new(Method::Put, Url::parse("https://site1.com/upload")?),
            Some("upload"),
            Some(&icon_hash),
            Some(Utc::now().timestamp() + 10),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        req.set_body(ICON_BYTES);
        let mut response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Created);
        let response_json: BlossomBlobDescriptor = response.body_json().await?;
        let icon_url = response_json.url;
        assert_eq!(response_json.r#type, "image/png");
        assert_eq!(response_json.sha256, icon_hash);
        assert_eq!(response_json.size, ICON_BYTES.len());
        assert_eq!(icon_url, expected_icon_url);

        // get the file
        let req = Request::new(Method::Options, Url::parse(&icon_url)?);
        let response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Ok);
        assert_eq!(response.header("Access-Control-Allow-Origin").unwrap(), "*");
        let req = Request::new(Method::Get, Url::parse(&icon_url)?);
        let mut response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Ok);
        let response = response.body_bytes().await?;
        assert_eq!(response, ICON_BYTES);

        // /list
        let req = Request::new(
            Method::Options,
            Url::parse(&format!("https://site1.com/list/{}", leader_monkey_pubkey))?,
        );
        let response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Ok);
        assert_eq!(response.header("Access-Control-Allow-Origin").unwrap(), "*");
        let req = Request::new(
            Method::Get,
            Url::parse(&format!("https://site1.com/list/{}", leader_monkey_pubkey))?,
        );
        let mut response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Ok);
        let mut response_json: Vec<BlossomBlobDescriptor> = response.body_json().await?;
        assert_eq!(response_json.len(), 1);
        let response_json_element = response_json.pop().unwrap();
        assert_eq!(response_json_element.r#type, "image/png");
        assert_eq!(response_json_element.sha256, icon_hash);
        assert_eq!(response_json_element.size, ICON_BYTES.len());
        assert_eq!(response_json_element.url, expected_icon_url);

        // /delete with somebody else's key
        let req = with_blossom_auth_header(
            Request::new(
                Method::Delete,
                Url::parse(&format!("https://site1.com/{}", icon_hash))?,
            ),
            Some("delete"),
            Some(&icon_hash),
            Some(Utc::now().timestamp() + 10),
            WHAT_BLEAK_PRIVATE_KEY,
        );
        let response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Unauthorized);

        // /delete invalid 'x' tag
        let req = with_blossom_auth_header(
            Request::new(
                Method::Delete,
                Url::parse(&format!("https://site1.com/{}", icon_hash))?,
            ),
            Some("delete"),
            Some("a"),
            Some(Utc::now().timestamp() + 10),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        let mut response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Unauthorized);
        let response = response.body_string().await?;
        assert!(response.contains("Blossom: Invalid 'x' tag"));

        // /delete OK
        let req = with_blossom_auth_header(
            Request::new(
                Method::Delete,
                Url::parse(&format!("https://site1.com/{}", icon_hash))?,
            ),
            Some("delete"),
            Some(&icon_hash),
            Some(Utc::now().timestamp() + 10),
            LEADER_MONKEY_PRIVATE_KEY,
        );
        let response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Ok);

        // /list
        let req = Request::new(
            Method::Get,
            Url::parse(&format!("https://site1.com/list/{}", leader_monkey_pubkey))?,
        );
        let mut response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::Ok);
        let response_json: Vec<BlossomBlobDescriptor> = response.body_json().await?;
        assert_eq!(response_json.len(), 0);

        // try to get the file we just deleted
        let req = Request::new(Method::Get, Url::parse(&expected_icon_url)?);
        let response: Response = app.respond(req).await?;
        assert_eq!(response.status(), StatusCode::NotFound);

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
        let port = 8000;
        let bind_addr = format!("127.0.0.1:{port}");
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

        let ws_addr = format!("ws://{}/?test.com", &bind_addr);

        let _server_task = spawn(async move { app.listen(bind_addr).await });
        sleep(std::time::Duration::from_secs(1)).await;

        let (mut ws_stream, _) = connect_async(ws_addr).await?;

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

    async fn change_theme(
        site_api_url: &str,
        domain: &str,
        keys: &Keys,
        desired_theme: &str,
    ) -> Result<()> {
        let res = surf::put(site_api_url)
            .header(
                "Authorization",
                get_nostr_auth_header(site_api_url, "PUT", &keys.secret_key().to_secret_hex()),
            )
            .header("X-Target-Host", domain)
            .body_json(&serde_json::json!({"theme": desired_theme}))
            .map_err(|e| anyhow!(e.to_string()))?
            .await
            .map_err(|e| anyhow!(e.to_string()))?;

        assert_eq!(res.status(), StatusCode::Ok);

        Ok(())
    }

    async fn check_url(url: &str, contains: &[&str], does_not_contain: &[&str]) -> Result<()> {
        let mut res = surf::get(&url).await.expect("Failed to send request");

        assert_eq!(res.status(), 200, "Unexpected status code");

        let body = res.body_string().await.expect("Failed to read body");

        for c in contains {
            assert!(body.contains(c));
        }

        for c in does_not_contain {
            assert!(!body.contains(c));
        }

        Ok(())
    }

    #[async_std::test]
    async fn test_e2e() -> Result<()> {
        let port = 8001;
        let test_domain = "test.com";
        let bind_addr = format!("localhost:{port}");
        let tmp_dir = TempDir::new(TEST_ROOT_DIR_PREFIX).unwrap();
        let root_path = tmp_dir.path().to_str().unwrap();

        // fetch some themes

        download_test_themes(root_path).unwrap();

        let themes = theme::load_themes(root_path);
        let mut sites = site::load_sites(root_path, &themes, &None)?;

        let keys = Keys::generate();

        let Ok(site) = create_site(
            root_path,
            &test_domain,
            Some(keys.public_key.to_hex()),
            &themes,
            Some("hyde".to_string()),
        ) else {
            bail!("Cannot create site");
        };

        sites.insert(test_domain.to_string(), site);

        let app = server(
            root_path,
            Arc::new(RwLock::new(themes)),
            Arc::new(RwLock::new(sites)),
        )
        .await;

        let ws_addr = format!("ws://{}/?{}", bind_addr, test_domain);
        let homepage_url = format!("http://{}/?{}", bind_addr, test_domain);
        let post_url = format!("http://{}/posts/my-first-post/?{}", bind_addr, test_domain);
        let hyde_css_url = format!("http://{}/hyde.css?{}", bind_addr, test_domain);
        let site_api_url = format!("http://{}/api/config", bind_addr);

        let _server_task = spawn(async move { app.listen(bind_addr.to_string()).await });
        sleep(std::time::Duration::from_secs(1)).await;

        let (mut ws_stream, _) = connect_async(ws_addr).await?;

        check_url(
            &homepage_url,
            &vec![hyde_css_url.as_str()],
            &vec![post_url.as_str()],
        )
        .await?;

        // Make a blog post

        let post_content = "Hello post from rust-nostr!";
        let post = EventBuilder::long_form_text_note(post_content)
            .tag(Tag::identifier("my-first-post"))
            .sign_with_keys(&keys)?;

        send_client_message(&mut ws_stream, ClientMessage::event(post.clone())).await?;

        read_ok(&mut ws_stream, post.id).await?;

        check_url(
            &homepage_url,
            &vec![hyde_css_url.as_str(), post_url.as_str()],
            &vec![],
        )
        .await?;

        check_url(&post_url, &vec!["Hello post from rust-nostr!"], &vec![]).await?;

        change_theme(&site_api_url, test_domain, &keys, "pico").await?;

        check_url(&homepage_url, &vec![], &vec!["hyde.css"]).await?;

        check_url(&post_url, &vec!["Hello post from rust-nostr!"], &vec![]).await?;

        change_theme(&site_api_url, test_domain, &keys, "hyde").await?;

        check_url(
            &homepage_url,
            &vec![hyde_css_url.as_str(), post_url.as_str()],
            &vec![],
        )
        .await?;

        // Delete the post

        let all_events = query_relay(&mut ws_stream, Filter::new()).await?;

        let event_id = all_events[0].id;

        let delete = EventBuilder::delete(vec![event_id]).sign_with_keys(&keys)?;
        send_client_message(&mut ws_stream, ClientMessage::event(delete.clone())).await?;

        read_ok(&mut ws_stream, delete.id).await?;

        check_url(
            &homepage_url,
            &vec![hyde_css_url.as_str()],
            &vec![post_url.as_str()],
        )
        .await?;

        Ok(())
    }

    #[async_std::test]
    async fn test_template_functions() -> Result<()> {
        let port = 8002;
        let test_domain = "test.com";
        let bind_addr = format!("localhost:{port}");
        let tmp_dir = TempDir::new(TEST_ROOT_DIR_PREFIX).unwrap();
        let root_path = tmp_dir.path().to_str().unwrap();

        // generate two themes

        fs::create_dir_all(format!("{}/themes/with-optional/templates", root_path))?;
        fs::write(
            format!("{}/themes/with-optional/config.toml", root_path),
            "title = \"Fake theme with optional load\"\n",
        )?;
        fs::write(
            format!("{}/themes/with-optional/templates/index.html", root_path),
            "<html><body>123{{ load_data(d=\"test-data-1\", required=false) | safe }}456</body></html>",
        )?;

        fs::create_dir_all(format!("{}/themes/with-required/templates", root_path))?;
        fs::write(
            format!("{}/themes/with-required/config.toml", root_path),
            "title = \"Fake theme with required load\"\n",
        )?;
        fs::write(
            format!("{}/themes/with-required/templates/index.html", root_path),
            "<html><body>123{{ load_data(d=\"test-data-2\") | safe }}456</body></html>",
        )?;

        let themes = theme::load_themes(root_path);
        let mut sites = site::load_sites(root_path, &themes, &None)?;

        let keys = Keys::generate();

        let Ok(site) = create_site(
            root_path,
            &test_domain,
            Some(keys.public_key.to_hex()),
            &themes,
            Some("with-optional".to_string()),
        ) else {
            bail!("Cannot create site");
        };

        sites.insert(test_domain.to_string(), site);

        let app = server(
            root_path,
            Arc::new(RwLock::new(themes)),
            Arc::new(RwLock::new(sites)),
        )
        .await;

        let homepage_url = format!("http://{}/?{}", bind_addr, test_domain);

        let ws_addr = format!("ws://{}/?test.com", &bind_addr);
        let site_api_url = format!("http://{}/api/config", bind_addr);

        let _server_task = spawn(async move { app.listen(bind_addr.to_string()).await });
        sleep(std::time::Duration::from_secs(1)).await;

        let (mut ws_stream, _) = connect_async(ws_addr).await?;

        check_url(&homepage_url, &vec!["123456"], &vec![]).await?;

        // post custom data

        let data = EventBuilder::new(Kind::ApplicationSpecificData, "ASDFGHJK")
            .tag(Tag::identifier("test-data-1"))
            .sign_with_keys(&keys)?;

        send_client_message(&mut ws_stream, ClientMessage::event(data.clone())).await?;

        read_ok(&mut ws_stream, data.id).await?;

        check_url(&homepage_url, &vec!["123ASDFGHJK456"], &vec![]).await?;

        change_theme(&site_api_url, test_domain, &keys, "with-required").await?;

        // check homepage

        let res = surf::get(&homepage_url)
            .await
            .expect("Failed to send request");

        assert_eq!(res.status(), 400, "Unexpected status code");

        // post custom data

        let data = EventBuilder::new(Kind::ApplicationSpecificData, "QWERTYUI")
            .tag(Tag::identifier("test-data-2"))
            .sign_with_keys(&keys)?;

        send_client_message(&mut ws_stream, ClientMessage::event(data.clone())).await?;

        read_ok(&mut ws_stream, data.id).await?;

        check_url(&homepage_url, &vec!["123QWERTYUI456"], &vec![]).await?;

        Ok(())
    }
}
