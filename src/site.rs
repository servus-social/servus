use anyhow::{anyhow, bail, Context, Result};
use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt, fs,
    fs::File,
    io::BufReader,
    path::Path,
    str,
    sync::{Arc, RwLock},
};
use tide::log;
use walkdir::WalkDir;

const DEFAULT_THEME: &str = "hyde";

use crate::{
    content, nostr,
    resource::{Resource, ResourceKind},
    template,
    theme::Theme,
};

#[derive(Debug)]
pub struct DuplicateKeyError {}

impl fmt::Display for DuplicateKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Cannot have a pubkey in _config.toml when a secret key was also passed"
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServusMetadata {
    pub version: String,
}

#[derive(Clone)]
pub struct Site {
    pub domain: String,
    pub config: SiteConfig,
    pub events: Arc<RwLock<HashMap<String, nostr::Event>>>,
    pub resources: Arc<RwLock<HashMap<String, Resource>>>,
    pub tera: Arc<RwLock<Option<tera::Tera>>>, // TODO: try to move this to Theme
}

fn default_feed_filename() -> String {
    return "atom.xml".to_string();
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SiteConfig {
    pub base_url: String,
    pub pubkey: Option<String>,

    #[serde(default)]
    pub theme: String,
    pub title: Option<String>,
    pub description: Option<String>,

    // required by some themes
    #[serde(default = "default_feed_filename")]
    pub feed_filename: String,
    #[serde(default)]
    pub build_search_index: bool,

    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

impl SiteConfig {
    pub fn empty(base_url: &str, theme: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            pubkey: None,
            theme: theme.to_string(),
            title: None,
            description: None,
            feed_filename: default_feed_filename(),
            build_search_index: false,
            extra: HashMap::new(),
        }
    }

    pub fn with_pubkey(self, pubkey: Option<String>) -> Self {
        Self { pubkey, ..self }
    }

    pub fn with_extra(
        mut self,
        extra_config: HashMap<String, toml::Value>,
        overwrite: bool,
    ) -> Self {
        for (k, v) in &extra_config {
            if overwrite && self.extra.contains_key(k) {
                self.extra.remove(k);
            }
            if !self.extra.contains_key(k) {
                self.extra.insert(k.to_string(), v.clone());
            }
        }
        self
    }

    // https://github.com/getzola/zola/blob/master/components/config/src/config/mod.rs

    /// Makes a url, taking into account that the base url might have a trailing slash
    pub fn make_permalink(&self, site_domain: &str, path: &str) -> String {
        let trailing_bit = if path.ends_with('/')
            || path.ends_with("atom.xml")
            || path.ends_with(".css")
            || path.is_empty()
        {
            ""
        } else {
            "/"
        };

        // Index section with a base url that has a trailing slash
        let permalink = if self.base_url.ends_with('/') && path == "/" {
            self.base_url.to_string()
        } else if path == "/" {
            // index section with a base url that doesn't have a trailing slash
            format!("{}/", self.base_url)
        } else if self.base_url.ends_with('/') && path.starts_with('/') {
            format!("{}{}{}", self.base_url, &path[1..], trailing_bit)
        } else if self.base_url.ends_with('/') || path.starts_with('/') {
            format!("{}{}{}", self.base_url, path, trailing_bit)
        } else {
            format!("{}/{}{}", self.base_url, path, trailing_bit)
        };

        if self.base_url.starts_with("http://localhost:")
            || self.base_url.starts_with("http://127.0.0.1:")
        {
            // rewrite links when running locally
            // to allow the server know what site they are referring to
            format!("{}?{}", permalink, site_domain)
        } else {
            permalink
        }
    }
}

pub fn load_templates(
    root_path: &str,
    site: &Site,
    site_domain: &str,
    site_config: &SiteConfig,
) -> Result<tera::Tera> {
    log::debug!("Loading templates...");

    let theme_path = format!("{}/themes/{}", root_path, site_config.theme);

    let mut tera = tera::Tera::new(&format!("{}/templates/**/*", theme_path))?;
    tera.autoescape_on(vec![]);
    tera.register_function(
        "get_url",
        template::GetUrl::new(site_domain.to_string(), site_config.clone()),
    );
    tera.register_function("load_data", template::LoadData::new(site.clone()));

    log::info!(
        "Loaded {} templates for {}",
        tera.get_template_names().count(),
        site_config.base_url
    );

    Ok(tera)
}

impl Site {
    pub fn empty(theme: &str) -> Self {
        let config = SiteConfig::empty(&"http://localhost/", theme);

        Site {
            domain: "localhost".to_string(),
            config,
            events: Arc::new(RwLock::new(HashMap::new())),
            resources: Arc::new(RwLock::new(HashMap::new())),
            tera: Arc::new(RwLock::new(Some(tera::Tera::default()))),
        }
    }

    #[cfg(test)]
    pub fn with_pubkey(mut self, pubkey: String) -> Self {
        self.config.pubkey = Some(pubkey);
        self
    }

    fn load_resources(&self, root_path: &str, secret_key: &Option<String>) -> Result<()> {
        let content_root = Path::new(root_path)
            .join("sites")
            .join(self.domain.to_string())
            .join("_content");

        if !content_root.exists() {
            // we simply assume that missing directory means no data
            return Ok(());
        }

        let Ok(mut events) = self.events.write() else {
            bail!("Cannot write events");
        };

        let Ok(mut resources) = self.resources.write() else {
            bail!("Cannot write resources");
        };

        for entry in WalkDir::new(&content_root) {
            let path = entry?.into_path();
            if !path.is_file() {
                continue;
            }
            let relative_path = path.strip_prefix(&content_root)?;
            if relative_path.starts_with("files/") {
                continue;
            }

            log::debug!("Scanning file {}...", path.display());
            let file = File::open(&path)?;
            let mut reader = BufReader::new(file);

            let (front_matter, content) = content::read(&mut reader)?;

            let event = match nostr::parse_event(&front_matter, &content) {
                Some(e) => e,
                _ => {
                    log::warn!("Cannot parse event from {}", path.display());

                    let Some(secret_key) = &secret_key else {
                        continue;
                    };

                    let file_stem = path.file_stem().unwrap().to_str().unwrap().to_string();

                    let mut bare_event =
                        nostr::BareEvent::new(nostr::EVENT_KIND_LONG_FORM, vec![], &content);

                    let mut date: Option<NaiveDateTime> = None;
                    if file_stem.len() > 11 {
                        let date_part = &file_stem[0..10];
                        if let Ok(d) = NaiveDate::parse_from_str(date_part, "%Y-%m-%d") {
                            let midnight = NaiveTime::from_hms_opt(0, 0, 0).unwrap();
                            date = Some(NaiveDateTime::new(d, midnight));
                        }
                    }

                    if let Some(date) = date {
                        bare_event.created_at = date.and_utc().timestamp();
                        bare_event
                            .tags
                            .push(vec!["d".to_string(), file_stem[11..].to_string()]);
                        log::info!("Generated new event for post: {}", path.display());
                    } else {
                        bare_event
                            .tags
                            .push(vec!["d".to_string(), file_stem.clone()]);
                        bare_event
                            .tags
                            .push(vec![String::from("t"), String::from("page")]);
                        log::info!("Generated new event for page: {}", path.display());
                    }
                    bare_event.tags.push(vec![
                        String::from("title"),
                        front_matter
                            .get("title")
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .to_string(),
                    ]);

                    bare_event.sign(&secret_key)
                }
            };

            log::info!("Event: id={}", &event.id);

            if let Some(kind) = get_resource_kind(&event) {
                let resource = Resource {
                    kind,
                    date: event.get_date(),
                    slug: if let Some(long_form_slug) = event.get_d_tag() {
                        long_form_slug
                    } else {
                        &event.id
                    }
                    .to_string(),
                    event_id: Some(event.id.clone()),
                };

                if let Some(url) = resource.get_resource_url() {
                    log::info!("Resource: url={}", &url);
                    resources.insert(url, resource);
                }

                events.insert(event.id.clone(), event);
            };
        }

        Ok(())
    }

    fn get_path(
        &self,
        root_path: &str,
        event_kind: u64,
        resource_kind: &Option<ResourceKind>,
        event_id: &str,
        event_d_tag: Option<&str>,
    ) -> String {
        // TODO: read all this from config
        Path::new(root_path)
            .join("sites")
            .join(&self.domain)
            .join("_content")
            .join(match (event_kind, resource_kind) {
                (nostr::EVENT_KIND_CUSTOM_DATA, _) => format!("data/{}.md", event_d_tag.unwrap()),
                (_, Some(ResourceKind::Post)) => format!("posts/{}.md", event_d_tag.unwrap()),
                (_, Some(ResourceKind::Page)) => format!("pages/{}.md", event_d_tag.unwrap()),
                (_, Some(ResourceKind::Note)) => format!("notes/{}.md", event_id),
                (_, Some(ResourceKind::Picture)) => format!("pictures/{}.md", event_id),
                (_, Some(ResourceKind::Listing)) => format!("listings/{}.md", event_d_tag.unwrap()),
                _ => format!("events/{}.md", event_id),
            })
            .display()
            .to_string()
    }

    pub fn add_content(&self, root_path: &str, event: &nostr::Event) -> Result<()> {
        let event_d_tag = event.get_d_tag();
        let kind = get_resource_kind(event);

        let filename = self.get_path(root_path, event.kind, &kind, &event.id, event_d_tag.clone());
        event.write(&filename)?;

        let Ok(mut events) = self.events.write() else {
            bail!("Cannot write events");
        };

        let Ok(mut resources) = self.resources.write() else {
            bail!("Cannot write resources");
        };

        if event.is_parameterized_replaceable() {
            let mut matched_event_id: Option<String> = None;
            {
                if event_d_tag.is_some() {
                    for event in events.values() {
                        if event.get_d_tag().as_deref() == event_d_tag {
                            matched_event_id = Some(event.id.to_owned());
                        }
                    }
                }
            }
            if let Some(matched_event_id) = matched_event_id {
                log::info!("Removing (outdated) event: {}!", &matched_event_id);
                events.remove(&matched_event_id);
            }
        }

        if let Some(kind) = kind {
            let resource = Resource {
                kind,
                date: event.get_date(),
                slug: if let Some(long_form_slug) = event_d_tag {
                    long_form_slug
                } else {
                    &event.id
                }
                .to_string(),
                event_id: Some(event.id.to_owned()),
            };

            if let Some(url) = resource.get_resource_url() {
                // but not all posts have an URL (drafts don't)
                resources.insert(url.to_owned(), resource);
            }
        }

        events.insert(event.id.to_owned(), event.clone());

        Ok(())
    }

    pub fn remove_content(&self, root_path: &str, deletion_event: &nostr::Event) -> Result<bool> {
        let mut deleted_event_id: Option<&str> = None;
        let mut deleted_event_kind: Option<u64> = None;
        let mut deleted_event_d_tag: Option<&str> = None;
        for tag in &deletion_event.tags {
            if tag[0] == "e" {
                deleted_event_id = Some(&tag[1]);
                log::debug!("DELETE 'e' {}", tag[1]);
            }
            if tag[0] == "a" {
                let deleted_event_ref = &tag[1];
                let parts = deleted_event_ref.split(':').collect::<Vec<_>>();
                if parts.len() == 3 {
                    if parts[1] != deletion_event.pubkey {
                        // TODO: do we need to check the site owner here?
                        return Ok(false);
                    }
                    deleted_event_kind = Some(parts[0].parse::<u64>().unwrap());
                    deleted_event_d_tag = Some(parts[2]);
                    log::debug!("DELETE 'a' {}", deleted_event_ref);
                }
            }
        }

        let mut resource_url: Option<String> = None;
        let mut resource_kind: Option<ResourceKind> = None;
        {
            let Ok(resources) = self.resources.read() else {
                bail!("Cannot access resources");
            };
            let Ok(events) = self.events.read() else {
                bail!("Cannot access events");
            };

            for (url, resource) in &*resources {
                let Some(resource_event_id) = &resource.event_id else {
                    continue;
                };

                let mut matched_resource = false;

                if let (Some(deleted_event_kind), Some(deleted_event_d_tag)) =
                    (deleted_event_kind, deleted_event_d_tag)
                {
                    let Some(event) = events.get(resource_event_id) else {
                        continue;
                    };
                    if let Some(event_d_tag) = event.get_d_tag() {
                        if event.kind == deleted_event_kind && event_d_tag == deleted_event_d_tag {
                            matched_resource = true;
                        }
                    }
                } else if let Some(deleted_event_id) = &deleted_event_id {
                    if resource_event_id == deleted_event_id {
                        matched_resource = true;
                    }
                }

                if matched_resource {
                    resource_url = Some(url.to_owned());
                    resource_kind = Some(resource.kind);
                }
            }
        }

        let mut matched_event_id: Option<String> = None;
        let mut path: Option<String> = None;
        {
            let Ok(events) = self.events.read() else {
                bail!("Cannot access events");
            };
            for (event_id, event) in &*events {
                let mut matched_event = false;
                if let (Some(deleted_event_kind), Some(deleted_event_d_tag)) =
                    (deleted_event_kind, deleted_event_d_tag)
                {
                    if let Some(event_d_tag) = event.get_d_tag() {
                        if event.kind == deleted_event_kind && event_d_tag == deleted_event_d_tag {
                            matched_event = true;
                        }
                    }
                } else if let Some(deleted_event_id) = &deleted_event_id {
                    if event_id == deleted_event_id {
                        matched_event = true;
                    }
                }

                if matched_event {
                    matched_event_id = Some(event.id.to_owned());
                    path = Some(self.get_path(
                        root_path,
                        event.kind,
                        &resource_kind,
                        event_id,
                        event.get_d_tag().as_deref(),
                    ));
                }
            }
        }

        if let Some(resource_url) = resource_url {
            log::info!("Removing resource: {}!", &resource_url);
            let Ok(mut resources) = self.resources.write() else {
                bail!("Cannot lock resources");
            };
            resources.remove(&resource_url);
        }

        if let Some(matched_event_id) = matched_event_id {
            log::info!("Removing event: {}!", &matched_event_id);
            let Ok(mut events) = self.events.write() else {
                bail!("Cannot lock events");
            };
            events.remove(&matched_event_id);
        }

        if let Some(path) = path {
            log::info!("Removing file: {}!", &path);
            fs::remove_file(path)?;
            Ok(true)
        } else {
            log::info!("No file for this resource!");
            Ok(false)
        }
    }
}

pub fn save_config(path: &str, config: &SiteConfig) -> Result<()> {
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

pub fn load_config(config_path: &str) -> Result<SiteConfig> {
    Ok(toml::from_str(&fs::read_to_string(config_path)?)?)
}

pub fn load_site(
    root_path: &str,
    domain: &str,
    themes: &HashMap<String, Theme>,
    secret_key: &Option<String>,
) -> Result<Site> {
    let path = format!("{}/sites/{}", root_path, domain);

    let mut config =
        load_config(&format!("{}/_config.toml", path)).context("Cannot load site config")?;

    if config.pubkey.is_some() && secret_key.is_some() {
        bail!(DuplicateKeyError {});
    }

    let theme_path = format!("{}/themes/{}", root_path, config.theme);
    if !Path::new(&theme_path).exists() {
        bail!(format!("Cannot load site theme: {}", config.theme));
    }

    if let Some(theme) = themes.get(&config.theme) {
        let extra_config: HashMap<String, toml::Value> = toml::from_str(&theme.extra_config)?;
        config = config.with_extra(extra_config, false);
    }

    let mut site = Site {
        domain: domain.to_owned(),
        config: config.clone(),
        events: Arc::new(RwLock::new(HashMap::new())),
        resources: Arc::new(RwLock::new(HashMap::new())),
        tera: Arc::new(RwLock::new(None)),
    };

    match load_templates(root_path, &site, domain, &config) {
        Ok(tera) => {
            site.tera = Arc::new(RwLock::new(Some(tera)));
            site.load_resources(root_path, secret_key)?;
            return Ok(site);
        }
        Err(e) => {
            return Err(anyhow!(e));
        }
    }
}

pub fn load_sites(
    root_path: &str,
    themes: &HashMap<String, Theme>,
    secret_key: &Option<String>,
) -> Result<HashMap<String, Site>> {
    let paths = match fs::read_dir(format!("{}/sites", root_path)) {
        Ok(paths) => paths.map(|r| r.unwrap()).collect(),
        _ => vec![],
    };

    let mut sites = HashMap::new();
    for path in &paths {
        let file_name = path.file_name();
        let domain = file_name.to_str().unwrap();

        log::info!("Found site: {}!", domain);
        match load_site(root_path, &domain, themes, secret_key) {
            Ok(site) => {
                sites.insert(path.file_name().to_str().unwrap().to_string(), site);
                log::debug!("Site loaded!");
            }
            Err(e) => {
                if let Some(_) = e.downcast_ref::<DuplicateKeyError>() {
                    bail!(e);
                } else {
                    log::warn!("Error loading site {}: {}", domain, e);
                }
            }
        }
    }

    log::info!("{} sites loaded!", sites.len());

    Ok(sites)
}

pub fn create_site(
    root_path: &str,
    domain: &str,
    admin_pubkey: Option<String>,
    themes: &HashMap<String, Theme>,
    theme: Option<String>,
) -> Result<Site> {
    let path = format!("{}/sites/{}", root_path, domain);

    if Path::new(&path).is_dir() {
        bail!("Directory already exists");
    }

    fs::create_dir_all(&path)?;

    let config = SiteConfig::empty(
        &format!("https://{}", domain),
        &theme.unwrap_or(DEFAULT_THEME.to_string()),
    )
    .with_pubkey(admin_pubkey);

    let config_path = &format!("{}/_config.toml", path);

    save_config(&config_path, &config)?;

    load_site(root_path, domain, themes, &None)
}

fn get_resource_kind(event: &nostr::Event) -> Option<ResourceKind> {
    match event.kind {
        nostr::EVENT_KIND_LONG_FORM | nostr::EVENT_KIND_LONG_FORM_DRAFT => {
            if event.is_page() {
                Some(ResourceKind::Page)
            } else {
                Some(ResourceKind::Post)
            }
        }
        nostr::EVENT_KIND_NOTE => Some(ResourceKind::Note),
        nostr::EVENT_KIND_PICTURE => Some(ResourceKind::Picture),
        nostr::EVENT_KIND_LISTING => Some(ResourceKind::Listing),
        _ => None,
    }
}
