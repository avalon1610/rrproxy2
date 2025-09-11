use anyhow::Result;
use hyper::{HeaderMap, header::HeaderName};

const OB_MAP: &[(&str, &str)] = &[
    (
        "proxy.individual.githubcopilot.com",
        "cdn1.mirrors6.tuna.tsinghua.edu.cn",
    ),
    ("github", "aliyun"),
    ("GitHub", "AliYun"),
    ("copilot", "outline"),
    ("chat", "bold"),
    ("vscode", "margin"),
    ("openai", "active"),
];

// Reverse mapping for "decode" pass.
// WARNING: This is not a true inverse if obfuscated tokens may appear originally.
const OB_MAP_REV: &[(&str, &str)] = &[
    (
        "cdn1.mirrors6.tuna.tsinghua.edu.cn",
        "proxy.individual.githubcopilot.com",
    ),
    ("aliyun", "github"),
    ("AliYun", "GitHub"),
    ("outline", "copilot"),
    ("bold", "chat"),
    ("margin", "vscode"),
    ("active", "openai"),
];

pub(crate) struct Obfuscator {}

impl Obfuscator {
    // Lazily apply OB_MAP; returns Some(String) only if something changed.
    #[inline]
    fn apply_map(s: &str, map: &[(&str, &str)]) -> Option<String> {
        let mut acc: Option<String> = None;
        for (k, v) in map {
            if let Some(current) = &mut acc {
                if current.contains(k) {
                    let replaced = current.replace(k, v);
                    *current = replaced;
                }
            } else if s.contains(k) {
                acc = Some(s.replace(k, v));
            }
        }
        acc
    }

    fn rewrite_headers(headers: &mut HeaderMap, map: &[(&str, &str)]) -> Result<()> {
        let mut to_remove = Vec::new();
        let mut to_insert = Vec::new();

        for (key, value) in headers.iter_mut() {
            let old_key_str = key.as_str();
            if let Some(new_key_str) = Self::apply_map(old_key_str, map) {
                // Key changed: schedule removal and insertion
                to_remove.push(key.clone());

                let new_name = HeaderName::from_bytes(new_key_str.as_bytes())?;

                // Preserve non-UTF-8 values; only transform UTF-8 values when needed
                let new_value = if let Ok(val_str) = value.to_str() {
                    if let Some(new_val_str) = Self::apply_map(val_str, map) {
                        new_val_str.parse()?
                    } else {
                        value.clone()
                    }
                } else {
                    value.clone()
                };

                to_insert.push((new_name, new_value));
            } else {
                // Key unchanged; maybe update value in-place (only if UTF-8 and actually changes)
                if let Ok(val_str) = value.to_str() {
                    if let Some(new_val_str) = Self::apply_map(val_str, map) {
                        *value = new_val_str.parse()?;
                    }
                }
            }
        }

        for key in to_remove {
            headers.remove(key);
        }

        for (key, value) in to_insert {
            headers.insert(key, value);
        }

        Ok(())
    }

    pub(crate) fn encode(headers: &mut HeaderMap) -> Result<()> {
        Self::rewrite_headers(headers, OB_MAP)
    }

    pub(crate) fn decode(headers: &mut HeaderMap) -> Result<()> {
        Self::rewrite_headers(headers, OB_MAP_REV)
    }
}
