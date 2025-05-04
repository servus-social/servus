// * Code taken from [Zola](https://www.getzola.org/) and adapted.
// * Zola's MIT license applies. See: https://github.com/getzola/zola/blob/master/LICENSE

use std::collections::HashMap;
use tera::{from_value, to_value, Function as TeraFn, Result as TeraResult, Value as TeraValue};

use crate::site::SiteConfig;

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
