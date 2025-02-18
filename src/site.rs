use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    fs::File,
    io::BufReader,
    path::Path,
    str,
    sync::{Arc, RwLock},
};
use tide::log;
use walkdir::WalkDir;

const DEFAULT_THEME: &str = "hyde";

// TODO: this should disappear
pub const SITE_PATH: &str = "./sites";

use crate::{
    content, nostr,
    resource::{Resource, ResourceKind},
    template, theme,
    theme::ThemeConfig,
    utils::merge,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct ServusMetadata {
    pub version: String,
}

#[derive(Clone)]
pub struct Site {
    pub domain: String,
    pub config: SiteConfig,
    pub events: Arc<RwLock<HashMap<String, EventRef>>>,
    pub resources: Arc<RwLock<HashMap<String, Resource>>>,
    pub tera: Arc<RwLock<tera::Tera>>, // TODO: try to move this to Theme
}

fn default_feed_filename() -> String {
    return "atom.xml".to_string();
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SiteConfig {
    pub base_url: String,
    pub pubkey: Option<String>,

    pub theme: String,
    pub title: Option<String>,

    #[serde(default = "default_feed_filename")]
    pub feed_filename: String, // required by some themes

    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

impl SiteConfig {
    pub fn empty(base_url: &str, theme: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            pubkey: None,
            theme: theme.to_string(),
            title: Some("".to_string()), // TODO: should be None?
            feed_filename: default_feed_filename(),
            extra: HashMap::new(),
        }
    }

    // https://github.com/getzola/zola/blob/master/components/config/src/config/mod.rs

    /// Makes a url, taking into account that the base url might have a trailing slash
    pub fn make_permalink(&self, path: &str) -> String {
        let trailing_bit = if path.ends_with('/') || path.ends_with("atom.xml") || path.is_empty() {
            ""
        } else {
            "/"
        };

        // Index section with a base url that has a trailing slash
        if self.base_url.ends_with('/') && path == "/" {
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
        }
    }

    pub fn merge(&mut self, other: &ThemeConfig) {
        for (key, value) in &other.extra {
            if ["base_url", "pubkey", "theme", "title"]
                .map(|s| s.to_string())
                .contains(key)
            {
                continue;
            }
            if !self.extra.contains_key(key) {
                self.extra.insert(key.to_owned(), value.clone());
                continue;
            }
            merge(self.extra.get_mut(key).unwrap(), value).unwrap();
        }
    }
}

fn load_templates(root_path: &str, site_config: &SiteConfig) -> Result<tera::Tera> {
    log::debug!("Loading templates...");

    let theme_path = format!("{}/themes/{}", root_path, site_config.theme);

    let mut tera = tera::Tera::new(&format!("{}/templates/**/*", theme_path))?;
    tera.autoescape_on(vec![]);
    tera.register_function("get_url", template::GetUrl::new(site_config.clone()));

    log::info!("Loaded {} templates!", tera.get_template_names().count());

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
            tera: Arc::new(RwLock::new(tera::Tera::default())),
        }
    }

    pub fn load_theme_config(&mut self, root_path: &str) -> Result<()> {
        let theme_config = theme::load_config(&format!(
            "{}/themes/{}/config.toml",
            root_path, self.config.theme
        ))?;
        self.config.merge(&theme_config);

        Ok(())
    }

    pub fn load_theme_templates(&mut self, root_path: &str) -> Result<()> {
        self.tera = Arc::new(RwLock::new(load_templates(root_path, &self.config)?));

        Ok(())
    }

    fn load_resources(&self, root_path: &str) {
        let content_root = Path::new(root_path)
            .join("sites")
            .join(self.domain.to_string())
            .join("_content");
        if !content_root.exists() {
            return;
        }

        for entry in WalkDir::new(&content_root) {
            let path = entry.unwrap().into_path();
            if !path.is_file() {
                continue;
            }
            let relative_path = path.strip_prefix(&content_root).unwrap();
            if relative_path.starts_with("files/") {
                continue;
            }

            log::debug!("Scanning file {}...", path.display());
            let file = File::open(&path).unwrap();
            let mut reader = BufReader::new(file);
            let filename = path.to_str().unwrap().to_string();
            let (front_matter, content) = content::read(&mut reader).unwrap();

            let Some(event) = nostr::parse_event(&front_matter, &content) else {
                log::warn!("Cannot parse event from {}.", filename);
                continue;
            };

            log::info!("Event: id={}.", &event.id);
            let event_ref = EventRef {
                id: event.id.to_owned(),
                created_at: event.created_at,
                kind: event.kind,
                d_tag: event.get_d_tag().map(|s| s.to_string()),
                filename,
            };
            let mut events = self.events.write().unwrap();
            events.insert(event.id.to_owned(), event_ref.clone());

            let Some(kind) = get_resource_kind(&event) else {
                continue;
            };

            let mut title: Option<String>;
            title = event.get_tags_hash().get("title").cloned();
            if title.is_none() && front_matter.contains_key("title") {
                title = Some(
                    front_matter
                        .get("title")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string(),
                );
            };

            let date = event.get_date();
            let slug = if let Some(long_form_slug) = event.get_d_tag() {
                long_form_slug.to_string()
            } else {
                event.id
            };

            let resource = Resource {
                kind,
                title,
                date,
                slug,
                event_id: Some(event_ref.id.to_owned()),
            };

            if let Some(url) = resource.get_resource_url() {
                log::info!("Resource: url={}.", &url);
                let mut resources = self.resources.write().unwrap();
                resources.insert(url, resource);
            }
        }
    }

    fn get_path(
        &self,
        event_kind: u64,
        resource_kind: &Option<ResourceKind>,
        event_id: &str,
        event_d_tag: Option<&str>,
    ) -> String {
        // TODO: read all this from config
        Path::new(&format!("{}/{}", SITE_PATH, self.domain))
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

    pub fn add_content(&self, event: &nostr::Event) {
        let event_d_tag = event.get_d_tag();
        let kind = get_resource_kind(event);
        let slug = if event.is_long_form() {
            event_d_tag.unwrap().to_string()
        } else {
            event.id.to_string()
        };

        let filename = self.get_path(event.kind, &kind, &event.id, event_d_tag.clone());
        event.write(&filename).unwrap();
        let event_ref = EventRef {
            id: event.id.to_owned(),
            created_at: event.created_at,
            kind: event.kind,
            d_tag: event_d_tag.map(|s| s.to_string()),
            filename,
        };

        let mut events = self.events.write().unwrap();

        if event.is_parameterized_replaceable() {
            let mut matched_event_id: Option<String> = None;
            {
                if event_d_tag.is_some() {
                    for event_ref in events.values() {
                        if event_ref.d_tag.as_deref() == event_d_tag {
                            matched_event_id = Some(event_ref.id.to_owned());
                        }
                    }
                }
            }
            if let Some(matched_event_id) = matched_event_id {
                log::info!("Removing (outdated) event: {}!", &matched_event_id);
                events.remove(&matched_event_id);
            }
        }

        events.insert(event.id.to_owned(), event_ref.clone());

        if let Some(kind) = kind {
            let resource = Resource {
                kind,
                title: event.get_tags_hash().get("title").cloned(),
                date: event.get_date(),
                slug,
                event_id: Some(event.id.to_owned()),
            };

            if let Some(url) = resource.get_resource_url() {
                // but not all posts have an URL (drafts don't)
                let mut resources = self.resources.write().unwrap();
                resources.insert(url.to_owned(), resource);
            }
        }
    }

    pub fn remove_content(&self, deletion_event: &nostr::Event) -> bool {
        let mut deleted_event_id: Option<String> = None;
        let mut deleted_event_kind: Option<u64> = None;
        let mut deleted_event_d_tag: Option<String> = None;
        for tag in &deletion_event.tags {
            if tag[0] == "e" {
                deleted_event_id = Some(tag[1].to_owned());
                log::debug!("DELETE 'e' {}", tag[1]);
            }
            if tag[0] == "a" {
                let deleted_event_ref = tag[1].to_owned();
                let parts = deleted_event_ref.split(':').collect::<Vec<_>>();
                if parts.len() == 3 {
                    if parts[1] != deletion_event.pubkey {
                        // TODO: do we need to check the site owner here?
                        return false;
                    }
                    deleted_event_kind = Some(parts[0].parse::<u64>().unwrap());
                    deleted_event_d_tag = Some(parts[2].to_owned());
                    log::debug!("DELETE 'a' {}", deleted_event_ref);
                }
            }
        }

        let mut resource_url: Option<String> = None;
        let mut resource_kind: Option<ResourceKind> = None;
        {
            let resources = self.resources.read().unwrap();
            for (url, resource) in &*resources {
                let Some(event_id) = resource.event_id.clone() else {
                    continue;
                };

                let mut matched_resource = false;

                if deleted_event_kind.is_some() && deleted_event_d_tag.is_some() {
                    let events = self.events.read().unwrap();
                    let event_ref = events.get(&event_id).unwrap();
                    if event_ref.kind == deleted_event_kind.unwrap()
                        && event_ref.d_tag == deleted_event_d_tag
                    {
                        matched_resource = true;
                    }
                } else if deleted_event_id.is_some() {
                    if Some(event_id) == deleted_event_id {
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
            let events = self.events.read().unwrap();
            for (event_id, event_ref) in &*events {
                let mut matched_event = false;
                if deleted_event_kind.is_some() && deleted_event_d_tag.is_some() {
                    if event_ref.kind == deleted_event_kind.unwrap()
                        && event_ref.d_tag == deleted_event_d_tag
                    {
                        matched_event = true;
                    }
                } else if deleted_event_id.is_some() {
                    if event_id == &deleted_event_id.clone().unwrap() {
                        matched_event = true;
                    }
                }

                if matched_event {
                    matched_event_id = Some(event_ref.id.to_owned());
                    path = Some(self.get_path(
                        event_ref.kind,
                        &resource_kind,
                        event_id,
                        event_ref.d_tag.as_deref(),
                    ));
                }
            }
        }

        if let Some(resource_url) = resource_url {
            log::info!("Removing resource: {}!", &resource_url);
            self.resources.write().unwrap().remove(&resource_url);
        }

        if let Some(matched_event_id) = matched_event_id {
            log::info!("Removing event: {}!", &matched_event_id);
            self.events.write().unwrap().remove(&matched_event_id);
        }

        if let Some(path) = path {
            log::info!("Removing file: {}!", &path);
            fs::remove_file(path).is_ok()
        } else {
            log::info!("No file for this resource!");
            false
        }
    }
}

#[derive(Clone, Serialize)]
pub struct EventRef {
    pub id: String,
    pub created_at: i64,
    pub kind: u64,
    pub d_tag: Option<String>,

    pub filename: String,
}

impl EventRef {
    pub fn read(&self) -> Option<(HashMap<String, serde_yaml::Value>, String)> {
        let file = File::open(&self.filename).unwrap();
        let mut reader = BufReader::new(file);

        content::read(&mut reader)
    }
}

pub fn save_config(path: &str, config: &SiteConfig) {
    fs::write(path, toml::to_string(&config).unwrap()).unwrap();
}

pub fn load_config(config_path: &str) -> Result<SiteConfig> {
    Ok(toml::from_str(&fs::read_to_string(config_path)?)?)
}

pub fn load_site(root_path: &str, domain: &str) -> Result<Site> {
    let path = format!("{}/sites/{}", root_path, domain);

    let mut config =
        load_config(&format!("{}/_config.toml", path)).context("Cannot load site config")?;

    let theme_path = format!("{}/themes/{}", root_path, config.theme);
    if !Path::new(&theme_path).exists() {
        bail!(format!("Cannot load site theme: {}", config.theme));
    }

    let theme_config = theme::load_config(&format!("{}/config.toml", theme_path))?;

    config.merge(&theme_config);

    match load_templates(root_path, &config) {
        Ok(tera) => {
            let site = Site {
                domain: domain.to_owned(),
                config,
                events: Arc::new(RwLock::new(HashMap::new())),
                resources: Arc::new(RwLock::new(HashMap::new())),
                tera: Arc::new(RwLock::new(tera)),
            };

            site.load_resources(root_path);

            return Ok(site);
        }
        Err(e) => {
            return Err(anyhow!(e));
        }
    }
}

pub fn load_sites(root_path: &str) -> HashMap<String, Site> {
    let paths = match fs::read_dir(format!("{}/sites", root_path)) {
        Ok(paths) => paths.map(|r| r.unwrap()).collect(),
        _ => vec![],
    };

    let mut sites = HashMap::new();
    for path in &paths {
        let file_name = path.file_name();
        let domain = file_name.to_str().unwrap();

        log::info!("Found site: {}!", domain);
        match load_site(root_path, &domain) {
            Ok(site) => {
                sites.insert(path.file_name().to_str().unwrap().to_string(), site);
                log::debug!("Site loaded!");
            }
            Err(e) => {
                log::warn!("Error loading site {}: {}", domain, e);
            }
        }
    }

    log::info!("{} sites loaded!", sites.len());

    sites
}

pub fn create_site(root_path: &str, domain: &str, admin_pubkey: Option<String>) -> Result<Site> {
    let path = format!("{}/sites/{}", root_path, domain);

    if Path::new(&path).is_dir() {
        bail!("Directory already exists");
    }

    fs::create_dir_all(&path)?;

    let config_content = format!(
        "pubkey = \"{}\"\nbase_url = \"https://{}\"\ntitle = \"{}\"\ntheme = \"{}\"\n[extra]\n",
        admin_pubkey.unwrap_or("".to_string()),
        domain,
        "",
        DEFAULT_THEME
    );
    fs::write(format!("{}/_config.toml", path), &config_content)
        .context("Cannot write config file")?;

    let mut config =
        load_config(&format!("{}/_config.toml", path)).context("Cannot read config file")?;

    let theme_path = format!("{}/themes/{}", root_path, config.theme);
    let theme_config = theme::load_config(&format!("{}/config.toml", theme_path))?;

    config.merge(&theme_config);

    let tera = load_templates(root_path, &config)?;

    let site = Site {
        domain: domain.to_owned(),
        config,
        events: Arc::new(RwLock::new(HashMap::new())),
        resources: Arc::new(RwLock::new(HashMap::new())),
        tera: Arc::new(RwLock::new(tera)),
    };

    site.load_resources(root_path);

    Ok(site)
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
