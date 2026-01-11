// * Code taken from [Zola](https://www.getzola.org/) and adapted.
// * Zola's MIT license applies. See: https://github.com/getzola/zola/blob/master/LICENSE

use image::{imageops::FilterType, ImageReader};
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    fs,
    hash::{Hash, Hasher},
    io::Read,
    path::Path,
    str::FromStr,
};
use tera::{
    from_value, to_value, try_get_value, Error as TeraError, Filter as TeraFilter,
    Function as TeraFn, Result as TeraResult, Value as TeraValue,
};

use crate::{nostr::EVENT_KIND_CUSTOM_DATA, site::Site};

// https://github.com/getzola/zola/blob/master/components/templates/src/global_fns/macros.rs

macro_rules! required_arg {
    ($ty: ty, $e: expr, $err: expr) => {
        match $e {
            Some(v) => match from_value::<$ty>(v.clone()) {
                Ok(u) => u,
                Err(_) => return Err($err.into()),
            },
            None => return Err($err.into()),
        }
    };
}

macro_rules! optional_arg {
    ($ty: ty, $e: expr, $err: expr) => {
        match $e {
            Some(v) => match from_value::<$ty>(v.clone()) {
                Ok(u) => Some(u),
                Err(_) => return Err($err.into()),
            },
            None => None,
        }
    };
}

// https://github.com/getzola/zola/blob/master/components/templates/src/global_fns/files.rs

pub struct GetUrl {
    _root_path: String,
    site: Site,
}

impl GetUrl {
    pub fn new(root_path: String, site: Site) -> Self {
        Self {
            _root_path: root_path,
            site,
        }
    }
}

impl TeraFn for GetUrl {
    fn call(&self, args: &HashMap<String, TeraValue>) -> TeraResult<TeraValue> {
        let path = required_arg!(
            String,
            args.get("path"),
            "`get_url` requires a `path` argument with a string value"
        );
        let trailing_slash = optional_arg!(
            bool,
            args.get("trailing_slash"),
            "`get_url`: `trailing_slash` must be a boolean (true or false)"
        )
        .unwrap_or(false);

        // anything else
        let mut segments = vec![];

        segments.push(path);

        let path = segments.join("/");

        let mut permalink = self
            .site
            .config
            .make_permalink(&self.site.domain, &path, None);
        if !trailing_slash && permalink.ends_with('/') {
            permalink.pop(); // Removes the slash
        }

        Ok(to_value(permalink).unwrap())
    }

    fn is_safe(&self) -> bool {
        true
    }
}

// https://github.com/getzola/zola/blob/master/components/templates/src/global_fns/load_data.rs

const GET_DATA_ARGUMENT_ERROR_MESSAGE: &str =
    "`load_data`: requires EITHER a `path`, a `d` or a `literal` argument";

enum OutputFormat {
    Json,
    Plain,
    Yaml,
}

impl FromStr for OutputFormat {
    type Err = TeraError;

    fn from_str(output_format: &str) -> TeraResult<Self> {
        match output_format.to_lowercase().as_ref() {
            "json" => Ok(OutputFormat::Json),
            "plain" => Ok(OutputFormat::Plain),
            "yaml" | "yml" => Ok(OutputFormat::Yaml),
            format => Err(format!("Unknown output format {}", format).into()),
        }
    }
}

fn get_output_format_from_args(format_arg: Option<String>) -> TeraResult<OutputFormat> {
    if let Some(format) = format_arg {
        return OutputFormat::from_str(&format);
    } else {
        // Always default to Plain if we don't know what it is
        Ok(OutputFormat::Plain)
    }
}

pub struct LoadData {
    root_path: String,
    site: Site,
}

impl LoadData {
    pub fn new(root_path: String, site: Site) -> Self {
        Self { root_path, site }
    }
}

impl TeraFn for LoadData {
    fn call(&self, args: &HashMap<String, TeraValue>) -> TeraResult<TeraValue> {
        let path_arg = optional_arg!(String, args.get("path"), GET_DATA_ARGUMENT_ERROR_MESSAGE);
        let d_arg = optional_arg!(String, args.get("d"), GET_DATA_ARGUMENT_ERROR_MESSAGE);
        let literal_arg =
            optional_arg!(String, args.get("literal"), GET_DATA_ARGUMENT_ERROR_MESSAGE);
        let format_arg = optional_arg!(
            String,
            args.get("format"),
            "`load_data`: `format` needs to be an argument with a string value, being one of the supported `load_data` file types (json, yaml, plain)"
        );
        let required = optional_arg!(
            bool,
            args.get("required"),
            "`load_data`: `required` must be a boolean (true or false)"
        )
        .unwrap_or(true);

        let data = match (path_arg, d_arg, literal_arg) {
            (Some(path), None, None) => read_file(&self.root_path, &path, &self.site),
            (None, Some(d), None) => read_data(&d, &self.site),
            (None, None, Some(literal)) => Ok(literal),
            _ => {
                return Err(GET_DATA_ARGUMENT_ERROR_MESSAGE.into());
            }
        };

        let data = match (data, required) {
            // If the file was not required, return a Null value to the template
            (Err(_), false) => {
                return Ok(TeraValue::Null);
            }
            (Err(e), true) => {
                return Err(e);
            }
            (Ok(data), _) => data,
        };

        let file_format = get_output_format_from_args(format_arg)?;

        let result_value: TeraResult<TeraValue> = match file_format {
            OutputFormat::Json => load_json(data),
            OutputFormat::Yaml => load_yaml(data),
            OutputFormat::Plain => to_value(data).map_err(|e| e.into()),
        };

        result_value
    }
}

fn read_file(root_path: &str, path: &str, site: &Site) -> TeraResult<String> {
    let mut content = String::new();
    let path = Path::new(root_path)
        .join("themes")
        .join(&site.config.theme)
        .join("static")
        .join(path);
    if path.exists() {
        fs::File::open(&path)?.read_to_string(&mut content)?;
        Ok(content)
    } else {
        Err(TeraError::msg(&format!(
            "File not found: {}.",
            path.display()
        )))
    }
}

fn read_data(d_tag: &str, site: &Site) -> TeraResult<String> {
    if let Ok(events) = site.events.read() {
        for event in events.values() {
            if event.kind == EVENT_KIND_CUSTOM_DATA {
                if let Some(event_d_tag) = event.get_d_tag() {
                    if event_d_tag == d_tag {
                        return Ok(event.content.clone());
                    }
                }
            }
        }
    };

    Err(TeraError::msg(format!("Event not found: {}.", d_tag)))
}

/// Parse a JSON string and convert it to a Tera Value
fn load_json(json_data: String) -> TeraResult<TeraValue> {
    let json_content: TeraValue =
        serde_json::from_str(json_data.as_str()).map_err(|e| format!("{:?}", e))?;
    Ok(json_content)
}

/// Parse a YAML string and convert it to a Tera Value
fn load_yaml(yaml_data: String) -> TeraResult<TeraValue> {
    let yaml_content: TeraValue =
        serde_yaml::from_str(yaml_data.as_str()).map_err(|e| format!("{:?}", e))?;
    Ok(yaml_content)
}

// https://github.com/getzola/zola/blob/master/components/templates/src/global_fns/images.rs

pub struct ResizeImage {
    root_path: String,
    site: Site,
}

impl ResizeImage {
    pub fn new(root_path: String, site: Site) -> Self {
        Self { root_path, site }
    }
}

impl TeraFn for ResizeImage {
    fn call(&self, args: &HashMap<String, TeraValue>) -> TeraResult<TeraValue> {
        let path = required_arg!(
            String,
            args.get("path"),
            "`resize_image` requires a `path` argument with a string value"
        );
        let width = required_arg!(
            u32,
            args.get("width"),
            "`resize_image`: `width` must be a non-negative integer"
        );
        let height = required_arg!(
            u32,
            args.get("height"),
            "`resize_image`: `height` must be a non-negative integer"
        );
        let op = optional_arg!(
            String,
            args.get("op"),
            "`resize_image`: `op` must be a string"
        )
        .unwrap_or_else(|| "fill".to_string());

        let site_path = format!("{}sites/{}", self.root_path, self.site.domain);
        let resource_path = format!("{}/_content/files/{}", site_path, path);

        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        width.hash(&mut hasher);
        height.hash(&mut hasher);
        op.hash(&mut hasher);
        let hash = hasher.finish();

        let cache_dir = format!("{}/cache", site_path);
        fs::create_dir_all(&cache_dir)?;

        let cache_filename = format!("{}.{:016x}", path, hash);

        let cache_url = format!(
            "/cache/{}{}",
            cache_filename,
            if self.site.config.is_local_server() {
                format!("?{}", self.site.domain)
            } else {
                "".to_string()
            }
        );

        if Path::new(&format!("{}/{}", cache_dir, cache_filename)).exists() {
            return Ok(to_value(
                &vec![("url", cache_url)]
                    .into_iter()
                    .collect::<HashMap<_, _>>(),
            )
            .map_err(|e| format!("{:?}", e))
            .unwrap());
        }

        let reader = ImageReader::open(resource_path)?.with_guessed_format()?;
        let format = reader.format().unwrap();
        let img = reader.decode().map_err(|e| format!("{:?}", e))?;

        match op.as_str() {
            "fit" => img.resize(width, height, FilterType::Lanczos3),
            "scale" => img.resize_exact(width, height, FilterType::Lanczos3),
            "fill" => img.resize_to_fill(width, height, FilterType::Lanczos3),
            _ => unreachable!(),
        }
        .save_with_format(format!("{}/{}", cache_dir, cache_filename), format)
        .map_err(|e| format!("{:?}", e))?;

        Ok(to_value(
            &vec![("url", format!("/cache/{}", cache_filename))]
                .into_iter()
                .collect::<HashMap<_, _>>(),
        )
        .map_err(|e| format!("{:?}", e))
        .unwrap())
    }
}

pub struct MarkdownFilter {}

impl MarkdownFilter {
    pub fn new() -> Self {
        Self {}
    }
}

impl TeraFilter for MarkdownFilter {
    fn filter(
        &self,
        value: &TeraValue,
        _args: &HashMap<String, TeraValue>,
    ) -> TeraResult<TeraValue> {
        let s = try_get_value!("markdown", "value", String, value);
        let parser = pulldown_cmark::Parser::new(&s);
        let mut html_output = String::new();
        pulldown_cmark::html::push_html(&mut html_output, parser);
        Ok(to_value(&html_output).unwrap())
    }
}
