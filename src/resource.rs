use anyhow::{bail, Result};
use chrono::NaiveDateTime;
use http_types::mime;
use serde::Serialize;
use std::{env, marker::PhantomData, path::PathBuf, str};

use crate::site::{ServusMetadata, Site};

#[derive(Clone, Copy, PartialEq, Serialize)]
pub enum ResourceKind {
    Post,
    Page,
    Note,
    Picture,
    Listing,
}

pub trait Renderable {
    fn from_resource(resource: &Resource, site: &Site) -> Result<Self>
    where
        Self: Sized;
    fn render(&self, site: &Site) -> Result<Vec<u8>>;
}

#[derive(Clone, Serialize)]
pub struct Page {
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
    word_count: usize,
}

impl Renderable for Page {
    fn from_resource(resource: &Resource, site: &Site) -> Result<Self> {
        let Some(resource_url) = resource.get_resource_url() else {
            bail!("Cannot render a resource without URL");
        };

        let Ok(events) = site.events.read() else {
            bail!("Cannot access events");
        };

        let mut title = String::new();
        let mut description = None;
        let mut summary = None;
        let mut content = String::new();

        if let Some(event_id) = &resource.event_id {
            if let Some(event) = events.get(event_id) {
                title = event.get_tag("title").unwrap_or("").to_owned();
                if event.is_note() {
                    description = Some(event.content.clone());
                }
                summary = event.get_long_form_summary().map(|s| s.to_string());
                let html_content = md_to_html(&event.content);
                if let Some(picture_url) = event.get_picture_url() {
                    let img_str = format!("<p><img src=\"{}\" /></p> ", picture_url);
                    content = String::with_capacity(html_content.len() + img_str.len());
                    content.push_str(&img_str);
                    content.push_str(&html_content);
                } else {
                    content = html_content;
                }
            }
        }

        Ok(Self {
            title,
            permalink: site.config.make_permalink(&resource_url),
            url: resource_url,
            slug: resource.slug.to_owned(),
            path: None, // TODO
            description,
            summary,
            word_count: content.split_whitespace().count(),
            content,
            date: resource.date,
            translations: vec![], // TODO
            lang: None,           // TODO
            reading_time: None,   // TODO
        })
    }

    fn render(&self, site: &Site) -> Result<Vec<u8>> {
        let Ok(mut tera) = site.tera.write() else {
            bail!("Cannot access tera");
        };

        let mut extra_context = tera::Context::new();

        // TODO: need real multilang support,
        // but for now, we just set this so that Zola themes don't complain
        extra_context.insert("lang", "en");

        extra_context.insert("current_url", &self.permalink);
        extra_context.insert("current_path", &self.url);

        extra_context.insert("config", &site.config);
        extra_context.insert("page", &self);

        Ok(
            render_template("page.html", &mut tera, &self.content, extra_context)?
                .as_bytes()
                .to_vec(),
        )
    }
}

trait SectionFilter {
    fn filter(k: ResourceKind) -> bool;
}

pub struct NoteSectionFilter;
impl SectionFilter for NoteSectionFilter {
    fn filter(k: ResourceKind) -> bool {
        k == ResourceKind::Note
    }
}

pub struct PostSectionFilter;
impl SectionFilter for PostSectionFilter {
    fn filter(k: ResourceKind) -> bool {
        k == ResourceKind::Post
    }
}

pub struct PictureSectionFilter;
impl SectionFilter for PictureSectionFilter {
    fn filter(k: ResourceKind) -> bool {
        k == ResourceKind::Picture
    }
}

pub struct ListingSectionFilter;
impl SectionFilter for ListingSectionFilter {
    fn filter(k: ResourceKind) -> bool {
        k == ResourceKind::Listing
    }
}

#[derive(Clone, Serialize)]
pub struct Section<T> {
    title: Option<String>,
    permalink: String,
    url: String,
    slug: String,
    path: Option<String>,
    pages: Vec<Page>,
    content: String,
    description: Option<String>,
    _phantom: PhantomData<T>,
}

impl<T> Renderable for Section<T>
where
    T: SectionFilter,
{
    fn from_resource(resource: &Resource, site: &Site) -> Result<Self> {
        let Some(resource_url) = resource.get_resource_url() else {
            bail!("Cannot render a resource without URL");
        };
        let Ok(resources) = site.resources.read() else {
            bail!("Cannot access resources");
        };
        let mut resources_list = resources.values().collect::<Vec<&Resource>>();
        resources_list.sort_by(|a, b| b.date.cmp(&a.date));
        let pages_list = resources_list
            .into_iter()
            .filter(|r| T::filter(r.kind))
            .map(|r| Page::from_resource(r, site))
            .filter_map(Result::ok)
            .collect::<Vec<Page>>();

        Ok(Self {
            title: None,
            permalink: site.config.make_permalink(&resource_url),
            url: resource_url,
            slug: resource.slug.to_owned(),
            path: None,        // TODO
            description: None, // TODO
            content: String::new(),
            pages: pages_list,
            _phantom: PhantomData,
        })
    }

    fn render(&self, site: &Site) -> Result<Vec<u8>> {
        let Ok(mut tera) = site.tera.write() else {
            bail!("Cannot access tera");
        };
        let mut extra_context = tera::Context::new();

        // TODO: need real multilang support,
        // but for now, we just set this so that Zola themes don't complain
        extra_context.insert("lang", "en");

        extra_context.insert("current_url", &self.permalink);
        extra_context.insert("current_path", &self.url);

        extra_context.insert("config", &site.config);

        // NB: some themes expect to iterate over section.pages, others look for paginator.pages.
        // We are currently passing both in all cases, so all themes will find the pages.
        extra_context.insert("section", &self);

        // TODO: paginator.pages should be paginated, but it is not.
        extra_context.insert(
            "paginator",
            &Paginator {
                current_index: 1,
                number_pagers: 1,
                pages: self.pages.clone(),
            },
        );

        // https://www.getzola.org/documentation/templates/pages-sections/
        let template = match self.slug.as_str() {
            "index" => "index.html",
            _ => "section.html",
        };

        Ok(
            render_template(&template, &mut tera, &self.content, extra_context)?
                .as_bytes()
                .to_vec(),
        )
    }
}

#[derive(Clone, Serialize)]
struct Paginator {
    current_index: usize,
    number_pagers: usize,
    pages: Vec<Page>,
}

#[derive(Clone, Serialize)]
pub struct Resource {
    pub kind: ResourceKind,
    pub slug: String,
    pub date: NaiveDateTime, // this is nice to have here for sorting
    pub event_id: Option<String>,
}

impl Resource {
    pub fn get_resource_url(&self) -> Option<String> {
        // TODO: extract all URL patterns from config!
        let slug = &self.slug;
        match self.kind {
            ResourceKind::Post => Some(format!("/posts/{}", &slug)),
            ResourceKind::Page => Some(format!("/{}", &slug)),
            ResourceKind::Note => Some(format!("/notes/{}", &slug)),
            ResourceKind::Picture => Some(format!("/pictures/{}", &slug)),
            ResourceKind::Listing => Some(format!("/listings/{}", &slug)),
        }
    }
}

fn render_template(
    template: &str,
    tera: &mut tera::Tera,
    content: &str,
    extra_context: tera::Context,
) -> Result<String, tera::Error> {
    let mut context = tera::Context::new();
    context.insert(
        "servus",
        &ServusMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    );
    context.insert("content", content);
    context.extend(extra_context);

    tera.render(template, &context)
}

fn render_robots_txt(site_url: &str) -> Result<(mime::Mime, String)> {
    let content = format!("User-agent: *\nSitemap: {}/sitemap.xml", site_url);
    Ok((mime::PLAIN, content))
}

fn render_nostr_json(site: &Site) -> (mime::Mime, String) {
    let content = format!(
        "{{ \"names\": {{ \"_\": \"{}\" }} }}",
        site.config.pubkey.clone().unwrap_or("".to_string())
    );
    (mime::JSON, content)
}

fn render_sitemap_xml(site_url: &str, site: &Site) -> Result<(mime::Mime, String)> {
    let Ok(resources) = site.resources.read() else {
        bail!("Cannot access resources");
    };
    let mut response = String::new();
    response.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    response.push_str("<urlset xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" ");
    response.push_str("xsi:schemaLocation=\"http://www.sitemaps.org/schemas/sitemap/0.9 ");
    response.push_str("http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd\" ");
    response.push_str("xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
    for url in resources.keys() {
        let mut url = url.trim_end_matches("/index").to_string();
        if url == site_url && !url.ends_with('/') {
            url.push('/');
        }
        response.push_str(&format!("    <url><loc>{}</loc></url>\n", &url));
    }
    response.push_str("</urlset>");

    Ok((mime::XML, response))
}

fn render_atom_xml(site_url: &str, site: &Site) -> Result<(mime::Mime, String)> {
    let Ok(resources) = site.resources.read() else {
        bail!("Cannot access resources");
    };
    let Ok(events) = site.events.read() else {
        bail!("Cannot access events");
    };

    let mut response = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n".to_owned();
    response.push_str("<feed xmlns=\"http://www.w3.org/2005/Atom\">\n");
    response.push_str(&format!(
        "<title>{}</title>\n",
        &site.config.title.clone().unwrap_or(String::new())
    ));
    response.push_str(&format!(
        "<link href=\"{}/atom.xml\" rel=\"self\"/>\n",
        site_url
    ));
    response.push_str(&format!("<link href=\"{}/\"/>\n", site_url));
    response.push_str(&format!("<id>{}</id>\n", site_url));
    for (url, resource) in &*resources {
        let Some(event_id) = &resource.event_id else {
            continue;
        };
        let Some(event) = events.get(event_id) else {
            continue;
        };
        response.push_str(&format!(
            "<entry>
<title>{}</title>
<link href=\"{}\"/>
<updated>{}</updated>
<id>{}/{}</id>
<content type=\"xhtml\"><div xmlns=\"http://www.w3.org/1999/xhtml\">{}</div></content>
</entry>
",
            event.get_tag("title").unwrap_or(&""),
            &url,
            &resource.date,
            site_url,
            &resource.slug,
            &md_to_html(&event.content)
        ));
    }
    response.push_str("</feed>");

    Ok((mime::XML, response))
}

pub fn render_standard_resource(
    resource_name: &str,
    site: &Site,
) -> Result<Option<(mime::Mime, String)>> {
    match resource_name {
        "robots.txt" => Ok(Some(render_robots_txt(&site.config.base_url)?)),
        ".well-known/nostr.json" => Ok(Some(render_nostr_json(site))),
        "sitemap.xml" => Ok(Some(render_sitemap_xml(&site.config.base_url, site)?)),
        "atom.xml" => Ok(Some(render_atom_xml(&site.config.base_url, site)?)),
        _ => Ok(None),
    }
}

fn md_to_html(md_content: &str) -> String {
    let parser = pulldown_cmark::Parser::new(md_content);
    let mut html_output = String::new();
    pulldown_cmark::html::push_html(&mut html_output, parser);
    html_output
}
