// * Code taken from [Zola](https://www.getzola.org/) and adapted.
// * Zola's MIT license applies. See: https://github.com/getzola/zola/blob/master/LICENSE

use std::collections::HashMap;
use std::str::FromStr;
use tera::{
    from_value, to_value, Error as TeraError, Function as TeraFn, Result as TeraResult,
    Value as TeraValue,
};

use crate::{
    nostr::EVENT_KIND_CUSTOM_DATA,
    site::{Site, SiteConfig},
};

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
    site_domain: String,
    site_config: SiteConfig,
}

impl GetUrl {
    pub fn new(site_domain: String, site_config: SiteConfig) -> Self {
        Self {
            site_domain,
            site_config,
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

        let mut permalink = self.site_config.make_permalink(&self.site_domain, &path);
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
    "`load_data`: requires EITHER a `d` or a `literal` argument";

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
    site: Site,
}

impl LoadData {
    pub fn new(site: Site) -> Self {
        Self { site }
    }
}

impl TeraFn for LoadData {
    fn call(&self, args: &HashMap<String, TeraValue>) -> TeraResult<TeraValue> {
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

        let data = if d_arg.is_some() && literal_arg.is_some() {
            return Err(GET_DATA_ARGUMENT_ERROR_MESSAGE.into());
        } else if let Some(d) = d_arg {
            read_data(&d, &self.site)
        } else if let Some(string_literal) = literal_arg {
            Ok(string_literal)
        } else {
            return Ok(GET_DATA_ARGUMENT_ERROR_MESSAGE.into());
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

    Err(TeraError::msg(format!(
        "Event identified by {} was not found",
        d_tag
    )))
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
