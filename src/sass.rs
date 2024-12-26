// * Code taken from [Zola](https://www.getzola.org/) and adapted.
// * Zola's MIT license applies. See: https://github.com/getzola/zola/blob/master/LICENSE

use anyhow::{anyhow, Result};
use globset::Glob;
use grass::{from_path as compile_file, Options, OutputStyle};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

// https://github.com/getzola/zola/blob/master/components/site/src/sass.rs

pub fn compile_sass(sass_path: &PathBuf) -> Result<HashMap<String, String>> {
    let mut resources = HashMap::new();

    let options = Options::default().style(OutputStyle::Compressed);
    let files = get_non_partial_scss(&sass_path);

    for file in files {
        match compile_file(&file, &options) {
            Ok(css) => {
                let path = file.strip_prefix(&sass_path).unwrap().with_extension("css");
                resources.insert(format!("/{}", path.display().to_string()), css);
            }
            _ => return Err(anyhow!(format!("Error compiling file: {}", file.display()))),
        }
    }

    Ok(resources)
}

fn is_partial_scss(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('_'))
        .unwrap_or(false)
}

fn get_non_partial_scss(sass_path: &Path) -> Vec<PathBuf> {
    let glob = Glob::new("*.{sass,scss}")
        .expect("Invalid glob for sass")
        .compile_matcher();

    WalkDir::new(sass_path)
        .into_iter()
        .filter_entry(|e| !is_partial_scss(e))
        .filter_map(|e| e.ok())
        .map(|e| e.into_path())
        .filter(|e| glob.is_match(e))
        .collect::<Vec<_>>()
}
