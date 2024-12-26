use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tide::log;

use crate::sass;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThemeConfig {
    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

pub fn load_config(config_path: &str) -> Result<ThemeConfig> {
    Ok(toml::from_str(&fs::read_to_string(config_path).context(
        format!("Config file not found: {}", config_path),
    )?)?)
}

pub struct Theme {
    pub path: String,
    pub config: ThemeConfig,
    pub resources: Arc<RwLock<HashMap<String, String>>>,
}

impl Theme {
    pub fn load_sass(&self) -> Result<()> {
        let mut sass_path = PathBuf::from(&self.path);
        sass_path.push("sass/");
        if !sass_path.as_path().exists() {
            return Ok(());
        }

        let mut resources = self.resources.write().unwrap();

        for (k, v) in &sass::compile_sass(&sass_path)? {
            log::debug!("Loaded theme resource: {}", k);
            resources.insert(k.to_owned(), v.to_string());
        }

        Ok(())
    }
}

fn load_theme(theme_path: &str) -> Result<Theme> {
    let config = load_config(&format!("{}/config.toml", theme_path))?;

    let theme = Theme {
        path: theme_path.to_string(),
        config,
        resources: Arc::new(RwLock::new(HashMap::new())),
    };

    theme.load_sass()?;

    Ok(theme)
}

pub fn load_themes() -> HashMap<String, Theme> {
    let paths = match fs::read_dir("./themes") {
        Ok(paths) => paths.map(|r| r.unwrap()).collect(),
        _ => vec![],
    };

    let mut themes = HashMap::new();
    for path in &paths {
        if !path.file_type().unwrap().is_dir()
            || path.file_name().to_str().unwrap().starts_with(".")
        {
            continue;
        }

        log::info!("Found theme: {}", path.file_name().to_str().unwrap());
        if let Ok(theme) = load_theme(&path.path().display().to_string()) {
            themes.insert(path.file_name().to_str().unwrap().to_string(), theme);
            log::debug!("Theme loaded!");
        }
    }

    log::info!("{} themes loaded!", themes.len());

    themes
}
