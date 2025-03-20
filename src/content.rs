use anyhow::{bail, Result};
use serde_yaml::Value as YamlValue;
use std::{collections::HashMap, io::BufRead};

pub fn read(reader: &mut dyn BufRead) -> Result<(HashMap<String, YamlValue>, String)> {
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            bail!("Nothing to read");
        }
        if !line.trim_end_matches('\n').is_empty() {
            break;
        }
    }
    if line.trim_end_matches('\n') != "---" {
        bail!("Cannot read front matter");
    }
    let mut yaml_front_matter = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        if line.trim_end_matches('\n') == "---" {
            break;
        }
        yaml_front_matter.push_str(&line);
    }

    let front_matter: HashMap<String, YamlValue> = serde_yaml::from_str(&yaml_front_matter)?;

    let mut content = String::new();
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        content.push_str(&line);
    }

    Ok((front_matter, content))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::BufReader;

    #[test]
    fn test_read() {
        let content = r#"
---
---
qwerty"#;
        let (front_matter, content) = read(&mut BufReader::new(content.as_bytes())).unwrap();
        assert_eq!(front_matter.len(), 0);
        assert_eq!(content, "qwerty");

        let content = r#"
---
asdf: ghjk
---
qwerty"#;
        let (front_matter, content) = read(&mut BufReader::new(content.as_bytes())).unwrap();
        assert_eq!(front_matter.len(), 1);
        assert_eq!(front_matter.get("asdf").unwrap().as_str().unwrap(), "ghjk");
        assert_eq!(content, "qwerty");

        let content = r#"
---
asdf: ghjk
---
qwerty


a
"#;
        let (front_matter, content) = read(&mut BufReader::new(content.as_bytes())).unwrap();
        assert_eq!(front_matter.len(), 1);
        assert_eq!(front_matter.get("asdf").unwrap().as_str().unwrap(), "ghjk");
        assert_eq!(content, "qwerty\n\n\na\n");

        let content = r#"
---
title: Matter --- Revenge of the Unquoted Strings
---
Some content."#;
        let (front_matter, content) = read(&mut BufReader::new(content.as_bytes())).unwrap();
        assert_eq!(front_matter.len(), 1);
        assert_eq!(
            front_matter.get("title").unwrap().as_str().unwrap(),
            "Matter --- Revenge of the Unquoted Strings"
        );
        assert_eq!(content, "Some content.");

        let content = r#"
---
availability: public
when:
    start: 1471/3/28 MTR 4::22
    duration: 0::30
date: 2012-02-18
title: Rutejìmo
---
Text"#;
        let (front_matter, content) = read(&mut BufReader::new(content.as_bytes())).unwrap();
        assert_eq!(front_matter.len(), 4);
        assert_eq!(
            front_matter.get("availability").unwrap().as_str().unwrap(),
            "public"
        );
        assert_eq!(
            front_matter
                .get("when")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("start")
                .unwrap()
                .as_str()
                .unwrap(),
            "1471/3/28 MTR 4::22"
        );
        assert_eq!(
            front_matter
                .get("when")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("duration")
                .unwrap()
                .as_str()
                .unwrap(),
            "0::30"
        );
        assert_eq!(
            front_matter.get("date").unwrap().as_str().unwrap(),
            "2012-02-18"
        );
        assert_eq!(
            front_matter.get("title").unwrap().as_str().unwrap(),
            "Rutejìmo"
        );
        assert_eq!(content, "Text");
    }
}
