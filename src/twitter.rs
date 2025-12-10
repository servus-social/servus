use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime};
use serde::Deserialize;
use std::{fs::File, io::Read};
use zip::ZipArchive;

#[derive(Debug, Deserialize, Clone)]
pub struct Tweet {
    pub full_text: String,

    pub in_reply_to_status_id: Option<String>,
    pub retweeted: bool,

    #[serde(deserialize_with = "deserialize_created_at")]
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Deserialize)]
struct TweetsJsEntry {
    tweet: Tweet,
}

fn deserialize_created_at<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(deserializer)?;
    let format = "%a %b %d %H:%M:%S %z %Y";

    DateTime::parse_from_str(&s, format)
        .map(|dt| dt.naive_utc())
        .map_err(D::Error::custom)
}

pub fn import_tweets(zip_path: &str) -> Result<impl Iterator<Item = Result<Tweet>>> {
    let file = File::open(zip_path).context("Failed to open file.")?;
    let mut archive = ZipArchive::new(file).context("Failed to read zip archive")?;

    let mut tweets_js = String::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i)?;
        if f.name().ends_with("data/tweets.js") {
            f.read_to_string(&mut tweets_js)?;
            break;
        }
    }

    let json_start = tweets_js
        .find('[')
        .ok_or_else(|| anyhow::anyhow!("Failed to parse tweet.js"))?;
    let json_str = &tweets_js[json_start..];

    let entries: Vec<TweetsJsEntry> = serde_json::from_str(json_str)?;
    Ok(entries
        .into_iter()
        .filter(|e| {
            e.tweet.in_reply_to_status_id.is_none()
                && !e.tweet.retweeted
                && !e.tweet.full_text.starts_with("RT @")
        })
        .map(|e| Ok(e.tweet)))
}
