use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};
use tide::log;

use crate::sass;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThemeConfig {
    pub name: String,
    pub description: String,
    pub license: Option<String>,
}

fn load_config(theme_path: &str) -> Result<ThemeConfig> {
    let config_path = format!("{}/theme.toml", theme_path);
    Ok(toml::from_str(&fs::read_to_string(&config_path).context(
        format!("Config file not found: {}", config_path),
    )?)?)
}

pub struct Theme {
    pub path: String,
    pub config: ThemeConfig,
    pub extra_config: String,
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
    let config = load_config(&theme_path)?;

    let theme = Theme {
        path: theme_path.to_string(),
        config,
        extra_config: extract_extra_sections(&format!("{}/config.toml", theme_path))?,
        resources: Arc::new(RwLock::new(HashMap::new())),
    };

    theme.load_sass()?;

    Ok(theme)
}

pub fn load_themes(root_path: &str) -> HashMap<String, Theme> {
    let mut themes = HashMap::new();

    if let Ok(rd) = fs::read_dir(Path::new(root_path).join("themes")) {
        for path in rd.map(|rd| rd.unwrap()) {
            if path.file_type().unwrap().is_dir()
                && !path.file_name().to_str().unwrap().starts_with(".")
            {
                log::info!("Found theme: {}", path.file_name().to_str().unwrap());
                if let Ok(theme) = load_theme(&path.path().display().to_string()) {
                    themes.insert(path.file_name().to_str().unwrap().to_string(), theme);
                    log::debug!("Theme loaded!");
                }
            }
        }
    }

    log::info!("{} themes loaded!", themes.len());

    themes
}

fn extract_extra_sections(config_path: &str) -> Result<String> {
    let file = File::open(config_path)?;
    let reader = BufReader::new(file);

    let mut result = String::new();
    let mut inside_extra_section = false;

    for line in reader.lines() {
        let line = line?;

        if let Some(section_name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            inside_extra_section = section_name == "extra" || section_name.starts_with("extra.");
        }

        if inside_extra_section {
            result.push_str(&line);
            result.push('\n');
        }
    }

    Ok(result)
}
