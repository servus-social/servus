use chrono::NaiveDateTime;
use http_types::mime;
use serde::Serialize;
use std::{collections::HashMap, env, fs::File, io::BufReader, path::PathBuf, str};

use crate::{
    content, nostr,
    site::{ServusMetadata, Site},
};

#[derive(Clone, Copy, PartialEq, Serialize)]
pub enum ResourceKind {
    Post,
    Page,
    Note,
}

#[derive(Clone, Serialize)]
pub enum ContentSource {
    Event(String),
    File(String),
    String(String),
}

#[derive(Clone, Serialize)]
struct Page {
    title: String,
    permalink: String,
    url: String,
    slug: String,
    path: Option<String>,
    description: Option<String>,
    summary: Option<String>,
    content: String,
    date: NaiveDateTime,
    translations: Vec<PathBuf>,
    lang: Option<String>,
    reading_time: Option<String>,
}

impl Page {
    fn from_resource(resource: &Resource, site: &Site) -> Self {
        let (front_matter, content) = resource.read(site).unwrap();
        let title;
        let summary;
        if let Some(event) = nostr::parse_event(&front_matter, &content) {
            title = event.get_tag("title").unwrap_or("".to_string()).to_owned();
            summary = event.get_long_form_summary();
        } else {
            title = front_matter
                .get("title")
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
            summary = None;
        }
        Self {
            title,
            permalink: site
                .config
                .make_permalink(&resource.get_resource_url().unwrap()),
            url: resource.get_resource_url().unwrap(),
            slug: resource.slug.to_owned(),
            path: None,        // TODO
            description: None, // TODO
            summary,
            content: md_to_html(&content),
            date: resource.date,
            translations: vec![], // TODO
            lang: None,           // TODO
            reading_time: None,   // TODO
        }
    }
}

#[derive(Clone, Serialize)]
struct Section {
    pages: Vec<Page>,
    title: Option<String>,
    content: Option<String>,
    description: Option<String>,
}

#[derive(Clone, Serialize)]
struct Paginator {
    pages: Vec<Page>,
}

#[derive(Clone, Serialize)]
pub struct Resource {
    pub kind: ResourceKind,
    pub slug: String,

    pub title: Option<String>,
    pub date: NaiveDateTime,

    pub content_source: ContentSource,
}

impl Resource {
    fn read(&self, site: &Site) -> Option<(HashMap<String, serde_yaml::Value>, String)> {
        let filename = match self.content_source.clone() {
            ContentSource::String(s) => {
                return Some((
                    HashMap::from([(
                        "title".to_string(),
                        serde_yaml::Value::String("".to_string()),
                    )]),
                    s,
                ))
            }
            ContentSource::File(f) => f,
            ContentSource::Event(e_id) => {
                let events = site.events.read().unwrap();
                let event_ref = events.get(&e_id).unwrap();
                event_ref.filename.to_owned()
            }
        };
        let file = File::open(filename).unwrap();
        let mut reader = BufReader::new(file);

        content::read(&mut reader)
    }

    pub fn get_resource_url(&self) -> Option<String> {
        // TODO: extract all URL patterns from config!
        match self.kind {
            ResourceKind::Post => Some(format!("/posts/{}", &self.slug)),
            ResourceKind::Page => Some(format!("/{}", &self.clone().slug)),
            ResourceKind::Note => Some(format!("/notes/{}", &self.clone().slug)),
        }
    }

    pub fn render(&self, site: &Site) -> Result<Vec<u8>, tera::Error> {
        let page = Page::from_resource(&self, &site);

        let mut tera = site.tera.write().unwrap();
        let mut extra_context = tera::Context::new();

        // TODO: need real multilang support,
        // but for now, we just set this so that Zola themes don't complain
        extra_context.insert("lang", "en");

        extra_context.insert("current_url", &page.permalink);
        extra_context.insert("current_path", &page.url);

        extra_context.insert("config", &site.config);
        extra_context.insert("data", &site.data);
        extra_context.insert("page", &page);

        let resources = site.resources.read().unwrap();
        let mut resources_list = resources.values().collect::<Vec<&Resource>>();
        resources_list.sort_by(|a, b| b.date.cmp(&a.date));
        let pages_list = resources_list
            .into_iter()
            .filter(|r| r.kind == ResourceKind::Post || r.kind == ResourceKind::Page)
            .map(|r| Page::from_resource(r, site))
            .collect::<Vec<Page>>();

        // NB: some themes expect to iterate over section.pages, others look for paginator.pages.
        // We are currently passing both in all cases, so all themes will find the pages.
        extra_context.insert(
            "section",
            &Section {
                pages: pages_list.clone(),
                title: None,       // TODO
                content: None,     // TODO
                description: None, // TODO
            },
        );
        // TODO: paginator.pages should be paginated, but it is not.
        extra_context.insert(
            "paginator",
            &Paginator {
                pages: pages_list.clone(),
            },
        );

        let template = if self.slug == "index" {
            "index.html"
        } else {
            "page.html"
        };

        Ok(
            render_template(&template, &mut tera, page.content, extra_context)?
                .as_bytes()
                .to_vec(),
        )
    }
}

fn render_template(
    template: &str,
    tera: &mut tera::Tera,
    content: String,
    extra_context: tera::Context,
) -> Result<String, tera::Error> {
    let mut context = tera::Context::new();
    context.insert(
        "servus",
        &ServusMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    );
    context.insert("content", &content);
    context.extend(extra_context);

    tera.render(template, &context)
}

fn render_robots_txt(site_url: &str) -> (mime::Mime, String) {
    let content = format!("User-agent: *\nSitemap: {}/sitemap.xml", site_url);
    (mime::PLAIN, content)
}

fn render_nostr_json(site: &Site) -> (mime::Mime, String) {
    let content = format!(
        "{{ \"names\": {{ \"_\": \"{}\" }} }}",
        site.config.pubkey.clone().unwrap_or("".to_string())
    );
    (mime::JSON, content)
}

fn render_sitemap_xml(site_url: &str, site: &Site) -> (mime::Mime, String) {
    let mut response: String = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n".to_owned();
    let resources = site.resources.read().unwrap();
    response.push_str("<urlset xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd\" xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
    for url in resources.keys() {
        let mut url = url.trim_end_matches("/index").to_owned();
        if url == site_url && !url.ends_with('/') {
            url.push('/');
        }
        response.push_str(&format!("    <url><loc>{}</loc></url>\n", url));
    }
    response.push_str("</urlset>");

    (mime::XML, response)
}

fn render_atom_xml(site_url: &str, site: &Site) -> (mime::Mime, String) {
    let mut response: String = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n".to_owned();
    response.push_str("<feed xmlns=\"http://www.w3.org/2005/Atom\">\n");
    response.push_str(&format!(
        "<title>{}</title>\n",
        &site.config.title.clone().unwrap_or("".to_string())
    ));
    response.push_str(&format!(
        "<link href=\"{}/atom.xml\" rel=\"self\"/>\n",
        site_url
    ));
    response.push_str(&format!("<link href=\"{}/\"/>\n", site_url));
    response.push_str(&format!("<id>{}</id>\n", site_url));
    let resources = site.resources.read().unwrap();
    for (url, resource) in &*resources {
        if let Some((_, content)) = resource.read(site) {
            response.push_str(
                &format!(
                    "<entry>
<title>{}</title>
<link href=\"{}\"/>
<updated>{}</updated>
<id>{}/{}</id>
<content type=\"xhtml\"><div xmlns=\"http://www.w3.org/1999/xhtml\">{}</div></content>
</entry>
",
                    resource.title.clone().unwrap_or("".to_string()),
                    &url,
                    &resource.date,
                    site_url,
                    resource.slug.clone(),
                    &md_to_html(&content).to_owned()
                )
                .to_owned(),
            );
        }
    }
    response.push_str("</feed>");

    (mime::XML, response)
}

pub fn render_standard_resource(resource_name: &str, site: &Site) -> Option<(mime::Mime, String)> {
    match resource_name {
        "robots.txt" => Some(render_robots_txt(&site.config.base_url)),
        ".well-known/nostr.json" => Some(render_nostr_json(site)),
        "sitemap.xml" => Some(render_sitemap_xml(&site.config.base_url, site)),
        "atom.xml" => Some(render_atom_xml(&site.config.base_url, site)),
        _ => None,
    }
}

fn md_to_html(md_content: &str) -> String {
    let parser = pulldown_cmark::Parser::new(md_content);
    let mut html_output = String::new();
    pulldown_cmark::html::push_html(&mut html_output, parser);
    html_output
}
