use std::env;

/// Where Servus keeps its files on disk.
#[derive(Clone, Debug)]
pub struct Paths {
    /// One directory per site, containing `_config.toml` and `_content/`.
    pub sites: String,
    /// One directory per theme. Downloaded on first run if empty.
    pub themes: String,
    /// Regenerable files, such as resized images, one directory per site.
    pub cache: String,
    /// Persistent state that is not content, such as ACME certificates.
    pub state: String,
}

impl Paths {
    /// Default locations, following the XDG base directory spec:
    /// sites in ~/Sites, themes in ~/.local/share/servus/themes,
    /// cache in ~/.cache/servus and state in ~/.local/state/servus.
    pub fn default() -> Self {
        let home = env::var("HOME").unwrap_or(".".to_string());

        Paths {
            sites: format!("{}/Sites", home),
            themes: format!(
                "{}/servus/themes",
                xdg_dir("XDG_DATA_HOME", &home, ".local/share")
            ),
            cache: format!("{}/servus", xdg_dir("XDG_CACHE_HOME", &home, ".cache")),
            state: format!(
                "{}/servus",
                xdg_dir("XDG_STATE_HOME", &home, ".local/state")
            ),
        }
    }

    /// All directories under a common root, as `<root>/sites`, `<root>/themes`, etc.
    #[cfg(test)]
    pub fn from_root(root: &str) -> Self {
        Paths {
            sites: format!("{}/sites", root),
            themes: format!("{}/themes", root),
            cache: format!("{}/cache", root),
            state: format!("{}/state", root),
        }
    }

    pub fn site(&self, domain: &str) -> String {
        format!("{}/{}", self.sites, domain)
    }

    pub fn theme(&self, theme: &str) -> String {
        format!("{}/{}", self.themes, theme)
    }

    pub fn site_cache(&self, domain: &str) -> String {
        format!("{}/{}", self.cache, domain)
    }

    pub fn acme(&self) -> String {
        format!("{}/acme", self.state)
    }
}

fn xdg_dir(var: &str, home: &str, default: &str) -> String {
    // The spec says relative paths in these variables are invalid and should be ignored.
    match env::var(var) {
        Ok(dir) if dir.starts_with('/') => dir,
        _ => format!("{}/{}", home, default),
    }
}
