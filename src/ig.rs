use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use scraper::{Html, Selector};
use std::{fs::File, io::Read};
use zip::read::ZipArchive;

pub struct Post {
    pub date: NaiveDateTime,
    pub image_data: Vec<u8>,
}

pub fn import_ig<'a>(zip_path: &str) -> Result<impl Iterator<Item = Result<Post>> + 'a> {
    let file = File::open(zip_path).context("Failed to open file.")?;
    let mut archive = ZipArchive::new(file).context("Failed to read zip archive")?;

    let mut html_data = String::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i)?;
        if f.name().contains("posts_1.html") {
            f.read_to_string(&mut html_data)?;
            break;
        }
    }

    let posts: Vec<Result<Post>> = Html::parse_document(&html_data)
        .select(&Selector::parse("div.pam").unwrap())
        .filter_map(|post| {
            let date = post
                .select(&Selector::parse("._3-94").unwrap())
                .next()
                .map(|t| t.text().collect::<String>())
                .unwrap_or("".into());

            let Ok(date) = NaiveDateTime::parse_from_str(&date, "%B %d, %Y %I:%M %p") else {
                println!("Unknown date");
                return None;
            };

            let img_src = post
                .select(&Selector::parse("img").unwrap())
                .next()
                .and_then(|img| img.value().attr("src"))
                .unwrap_or("".into());

            if img_src.is_empty() {
                println!("Image link not found");
                return None;
            }

            // For eager reading, reopen the zip
            let file = File::open(zip_path).ok()?;
            let mut archive = ZipArchive::new(file).ok()?;
            let mut image_data = Vec::new();
            archive
                .by_name(&img_src)
                .ok()?
                .read_to_end(&mut image_data)
                .ok()?;

            Some(Ok(Post { date, image_data }))
        })
        .collect();

    Ok(posts.into_iter())
}
