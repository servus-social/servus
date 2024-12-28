use anyhow::{bail, Context, Result};
use chrono::{DateTime, NaiveDateTime, TimeDelta, TimeZone, Utc};
use lazy_static::lazy_static;
use secp256k1::{schnorr, Secp256k1, VerifyOnly, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use serde_yaml::Value as YamlValue;
use std::collections::VecDeque;
use std::{
    collections::HashMap,
    fmt, fs,
    fs::File,
    io::Write,
    path::Path,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tide::log;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BareEvent {
    pub created_at: i64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

#[cfg(test)]
impl BareEvent {
    pub fn new(kind: u64, tags: Vec<Vec<String>>, content: &str) -> Self {
        Self {
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            kind,
            tags,
            content: content.to_string(),
        }
    }

    fn to_canonical(&self, pubkey: &str) -> String {
        let c = json!([
            0,
            pubkey.to_owned(),
            self.created_at,
            self.kind,
            self.tags,
            self.content.to_owned(),
        ]);

        serde_json::to_string(&c).unwrap()
    }

    pub fn sign(&self, key: &str) -> Event {
        let sk = secp256k1::SecretKey::from_str(key).unwrap();
        let keypair = secp256k1::KeyPair::from_secret_key(secp256k1::SECP256K1, &sk);
        let pubkey = hex::encode(keypair.public_key().x_only_public_key().0.serialize());

        let event_id = sha256::digest(self.to_canonical(&pubkey));

        let message = secp256k1::Message::from_slice(&hex::decode(&event_id).unwrap()).unwrap();
        let sig = keypair.sign_schnorr(message);

        Event {
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
            id: event_id.clone(),
            pubkey,
            sig: sig.to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

pub const EVENT_KIND_NOTE: u64 = 1;
pub const EVENT_KIND_DELETE: u64 = 5;
pub const EVENT_KIND_BLOSSOM: u64 = 24242;
pub const EVENT_KIND_AUTH: u64 = 27235;
pub const EVENT_KIND_LONG_FORM: u64 = 30023;
pub const EVENT_KIND_LONG_FORM_DRAFT: u64 = 30024;
pub const EVENT_KIND_CUSTOM_DATA: u64 = 30078;

lazy_static! {
    pub static ref SECP: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}

impl Event {
    pub fn is_parameterized_replaceable(&self) -> bool {
        return 30000 <= self.kind && self.kind < 40000;
    }

    pub fn is_long_form(&self) -> bool {
        self.kind == EVENT_KIND_LONG_FORM || self.kind == EVENT_KIND_LONG_FORM_DRAFT
    }

    pub fn get_date(&self) -> NaiveDateTime {
        if self.is_long_form() {
            if let Some(published_at) = self.get_long_form_published_at() {
                return published_at;
            }
        }

        self.get_created_at_date().naive_utc()
    }

    pub fn get_created_at_date(&self) -> DateTime<Utc> {
        Utc.timestamp_opt(self.created_at, 0).unwrap()
    }

    pub fn get_tags_hash(&self) -> HashMap<String, String> {
        let mut tags: HashMap<String, String> = HashMap::new();
        for t in &self.tags {
            tags.insert(t[0].to_owned(), t[1].to_owned());
        }
        tags
    }

    pub fn get_tag(&self, tag: &str) -> Option<String> {
        self.get_tags_hash().get(tag).cloned()
    }

    pub fn get_d_tag(&self) -> Option<String> {
        self.get_tag("d")
    }

    pub fn get_long_form_summary(&self) -> Option<String> {
        if self.kind != EVENT_KIND_LONG_FORM && self.kind != EVENT_KIND_LONG_FORM_DRAFT {
            return None;
        }

        self.get_tag("summary")
    }

    pub fn get_long_form_published_at(&self) -> Option<NaiveDateTime> {
        if self.kind != EVENT_KIND_LONG_FORM && self.kind != EVENT_KIND_LONG_FORM_DRAFT {
            return None;
        }

        let ts = self.get_tag("published_at")?.parse::<i64>().unwrap();

        DateTime::from_timestamp(ts, 0).map(|d| d.naive_utc())
    }

    pub fn validate_sig(&self) -> Result<()> {
        let canonical = self.to_canonical();
        log::debug!("Event in canonical format: {}", &canonical);

        let hash = bitcoin_hashes::sha256::Hash::hash(canonical.as_bytes());
        let hex_hash = format!("{:x}", hash);
        log::debug!("Event id: {}", self.id);
        log::debug!("Computed event id: {}", hash);

        if self.id != hex_hash {
            bail!("Invalid id");
        }

        match secp256k1::Message::from_slice(hash.as_ref()) {
            Ok(msg) => match XOnlyPublicKey::from_str(&self.pubkey) {
                Ok(pubkey) => {
                    let sig = schnorr::Signature::from_str(&self.sig).unwrap();
                    if SECP.verify_schnorr(&sig, &msg, &pubkey).is_err() {
                        bail!("Failed to verify signature")
                    } else {
                        Ok(())
                    }
                }
                Err(e) => bail!(e),
            },
            Err(e) => bail!(e),
        }
    }

    pub fn get_nip98_pubkey(&self, url: &str, method: &str) -> Result<String> {
        self.validate_sig()?;

        if self.kind != EVENT_KIND_AUTH || !self.content.is_empty() {
            bail!("NIP-98: Invalid event");
        }

        let now = chrono::offset::Utc::now();
        let five_mins = TimeDelta::minutes(5);
        let created_at = DateTime::from_timestamp(self.created_at as i64, 0).unwrap();
        if created_at < now && now - created_at > five_mins {
            bail!("NIP-98: Event too old");
        }
        if created_at > now && created_at - now > five_mins {
            bail!("NIP-98: Event too new");
        }

        let tags = self.get_tags_hash();
        let u_tag = tags.get("u").context("NIP-98: Missing 'u' tag")?;
        if u_tag != url {
            bail!("NIP-98: Invalid 'u' tag: {} vs. {}.", u_tag, url);
        }
        if tags.get("method").context("Missing 'method' tag")? != method {
            bail!("NIP-98: Invalid method");
        }

        Ok(self.pubkey.to_owned())
    }

    pub fn get_blossom_pubkey(&self, method: &str) -> Result<String> {
        self.validate_sig()?;

        if self.kind != EVENT_KIND_BLOSSOM {
            bail!("Blossom: Invalid event");
        }

        let now = SystemTime::now();
        let one_min = Duration::from_secs(60);
        let created_at = UNIX_EPOCH + Duration::from_secs(self.created_at as u64);
        if created_at > now.checked_add(one_min).unwrap() {
            bail!("Blossom: event too new");
        }

        let tags = self.get_tags_hash();
        if tags.get("t").context("Blossom: Missing 't' tag")? != method {
            bail!("Blossom: Invalid 't' tag");
        }
        let expiration = tags.get("expiration").context("Missing expiration")?;
        let expiration = UNIX_EPOCH + Duration::from_secs(expiration.parse::<u64>().unwrap());
        if expiration < now {
            bail!("Blossom: event expired");
        }

        Ok(self.pubkey.to_owned())
    }

    pub fn to_json(&self) -> JsonValue {
        json!({
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig,
        })
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(&self.to_json()).unwrap()
    }

    fn to_canonical(&self) -> String {
        let c = json!([
            0,
            self.pubkey.to_owned(),
            self.created_at,
            self.kind,
            self.tags,
            self.content.to_owned(),
        ]);

        serde_json::to_string(&c).unwrap()
    }

    pub fn write(&self, filename: &str) -> std::io::Result<()> {
        let path = Path::new(&filename);
        fs::create_dir_all(path.ancestors().nth(1).unwrap()).unwrap();
        let mut file;
        file = File::create(path).unwrap();

        writeln!(file, "---")?;
        writeln!(file, "id: {}", self.id)?;
        writeln!(file, "pubkey: {}", self.pubkey)?;
        writeln!(file, "created_at: {}", self.created_at)?;
        writeln!(file, "kind: {}", self.kind)?;
        writeln!(file, "tags:")?;
        for tag in self.tags.clone() {
            for (i, t) in tag.iter().enumerate() {
                if i == 0 {
                    writeln!(file, "- - {}", t)?;
                } else {
                    writeln!(file, "  - \"{}\"", t)?;
                }
            }
        }
        writeln!(file, "sig: {}", self.sig)?;
        writeln!(file, "---")?;
        write!(file, "{}", self.content)?;

        Ok(())
    }
}

fn get_metadata_tags(metadata: &HashMap<String, YamlValue>) -> Option<Vec<Vec<String>>> {
    let mut tags: Vec<Vec<String>> = vec![];
    if let Some(seq) = metadata.get("tags")?.as_sequence() {
        for tag in seq {
            let mut tag_vec: Vec<String> = vec![];
            for t in tag.as_sequence().unwrap() {
                tag_vec.push(t.as_str().unwrap().to_owned());
            }
            tags.push(tag_vec);
        }
    }

    Some(tags)
}

pub fn parse_event(front_matter: &HashMap<String, YamlValue>, content: &str) -> Option<Event> {
    Some(Event {
        id: front_matter.get("id")?.as_str()?.to_owned(),
        pubkey: front_matter.get("pubkey")?.as_str()?.to_owned(),
        created_at: front_matter.get("created_at")?.as_i64()?,
        kind: front_matter.get("kind")?.as_u64()?,
        tags: get_metadata_tags(front_matter)?,
        sig: front_matter.get("sig")?.as_str()?.to_owned(),
        content: content.trim_end_matches('\n').to_owned(),
    })
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Filter {
    pub authors: Option<Vec<String>>,
    pub kinds: Option<Vec<u64>>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<usize>,

    #[serde(flatten)]
    pub extra: HashMap<String, JsonValue>,
}

impl Filter {
    pub fn matches_author(&self, author: &str) -> bool {
        if let Some(authors) = &self.authors {
            authors
                .iter()
                .map(|a| author.starts_with(a))
                .fold(false, |acc, value| if acc { acc } else { value })
        } else {
            true
        }
    }

    pub fn matches_kind(&self, kind: &u64) -> bool {
        if let Some(kinds) = &self.kinds {
            kinds.contains(&kind)
        } else {
            true
        }
    }

    pub fn matches_time(&self, ts: &i64) -> bool {
        let matches_since = if let Some(since) = self.since {
            ts >= &since
        } else {
            true
        };
        let matches_until = if let Some(until) = self.until {
            ts < &until
        } else {
            true
        };

        matches_since && matches_until
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(authors) = &self.authors {
            write!(f, " authors: {}", authors.join(","))?;
        }
        if let Some(kinds) = &self.kinds {
            write!(
                f,
                " kinds: {}",
                kinds
                    .iter()
                    .map(|k| format!("{}", k))
                    .collect::<Vec<String>>()
                    .join(",")
            )?;
        }

        Ok(())
    }
}

#[derive(PartialEq, Clone, Copy, Debug, Deserialize, Serialize)]
pub enum MessageType {
    EVENT,
    REQ,
    CLOSE,
}

#[derive(PartialEq, Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ProtocolData {
    Type(MessageType),
    SubId(String),
    Event(Event),
    Filter(Filter),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Message {
    Event {
        event: Event,
    },
    Req {
        sub_id: String,
        filters: Vec<Filter>,
    },
    Close {
        sub_id: String,
    },
}

impl Message {
    pub fn from_str(s: &str) -> Result<Message, &'static str> {
        let mut data: VecDeque<ProtocolData> = serde_json::from_str(&s).unwrap();
        match data.pop_front().unwrap() {
            ProtocolData::Type(msg_type) => {
                if let Some(msg) = match msg_type {
                    MessageType::EVENT => Message::from_event(data),
                    MessageType::REQ => Message::from_req(data),
                    MessageType::CLOSE => Message::from_close(data),
                } {
                    Ok(msg)
                } else {
                    Err("Error decoding message.")
                }
            }
            _ => Err("Message must start with one of: \"EVENT\", \"REQ\", \"CLOSE\"."),
        }
    }

    fn from_event(mut data: VecDeque<ProtocolData>) -> Option<Message> {
        if let ProtocolData::Event(event) = data.pop_front().unwrap() {
            Some(Message::Event { event })
        } else {
            None
        }
    }

    fn from_req(mut data: VecDeque<ProtocolData>) -> Option<Message> {
        let sub_id: String = if let ProtocolData::SubId(sub_id) = data.pop_front().unwrap() {
            Some(sub_id)
        } else {
            None
        }?;

        let filters: Vec<Filter> = data
            .into_iter()
            .fold(Some(vec![]), |acc, entry| match acc {
                None => None,
                Some(mut acc) => match entry {
                    ProtocolData::Filter(filter) => {
                        acc.push(filter);
                        Some(acc)
                    }
                    _ => None,
                },
            })?;

        Some(Message::Req { sub_id, filters })
    }

    fn from_close(mut data: VecDeque<ProtocolData>) -> Option<Message> {
        if let ProtocolData::SubId(sub_id) = data.pop_front().unwrap() {
            Some(Message::Close { sub_id })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_event() {
        let id = "0ff0c8f57ddea79cb9f12c574b5056b712d584b9fe55118149ea4b343d3f89a7";
        let pubkey = "f982dbf2a0a4a484c98c5cbb8b83a1ecaf6589cb2652e19381158b5646fe23d6";
        let created_at = 1710006173;
        let sig = "39944d4aa9bdba0b6739d6ee126ae84cdbacb90e9b4412ff44bf91c1948525c07ef022c5941921c25154d08b2a43bd3c8f4e5181b905eaaef18957d89d01f598";
        let content = "qwerty";

        let front_matter = format!(
            "id: {}\npubkey: {}\ncreated_at: {}\nkind: 1\ntags:\nsig: {}\n",
            id, pubkey, created_at, sig
        );
        let event = parse_event(&serde_yaml::from_str(&front_matter).unwrap(), content).unwrap();

        assert_eq!(event.id, id);
        assert_eq!(event.pubkey, pubkey);
        assert_eq!(event.kind, 1);
        assert_eq!(event.sig, sig);
        assert_eq!(event.content, content);

        // front matter without id
        let front_matter = format!(
            "id:\npubkey: {}\ncreated_at: {}\nkind: 1\ntags:\nsig: {}\n",
            pubkey, created_at, sig
        );
        let no_event = parse_event(&serde_yaml::from_str(&front_matter).unwrap(), content);

        assert!(no_event.is_none());
    }

    #[test]
    fn test_parse_req() {
        let s = "[\"REQ\",\"subid\",{\"authors\":[\"a\"],\"kinds\":[0],\"limit\":1},{\"authors\":[\"b\"],\"kinds\":[3],\"limit\":2}]";
        let message = Message::from_str(&s).unwrap();

        if let Message::Req { sub_id, filters } = message {
            assert_eq!(sub_id, "subid");
            assert_eq!(filters.len(), 2);

            assert!(filters[0]
                .authors
                .as_ref()
                .unwrap()
                .contains(&"a".to_string()));
            assert!(!filters[0]
                .authors
                .as_ref()
                .unwrap()
                .contains(&"b".to_string()));
            assert!(filters[0].kinds.as_ref().unwrap().contains(&0));
            assert!(!filters[0].kinds.as_ref().unwrap().contains(&3));
            assert_eq!(filters[0].limit, Some(1));

            assert!(filters[1]
                .authors
                .as_ref()
                .unwrap()
                .contains(&"b".to_string()));
            assert!(!filters[1]
                .authors
                .as_ref()
                .unwrap()
                .contains(&"a".to_string()));
            assert!(filters[1].kinds.as_ref().unwrap().contains(&3));
            assert!(!filters[1].kinds.as_ref().unwrap().contains(&0));
            assert_eq!(filters[1].limit, Some(2));
        } else {
            assert!(false);
        }
    }
}
