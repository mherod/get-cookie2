use crate::types::Cookie;
use anyhow::Result;

pub enum OutputFormat {
    Plain,
    Json,
    Render,
}

/// Render cookies as an HTTP `Cookie` header value: `name=value; name=value`.
///
/// Deduplicates by name, keeping the most recent (last) cookie for each name
/// while preserving the original relative ordering of the retained cookies.
/// Shared by the `Render` output format and `--curl` command generation so both
/// paths produce identical header strings.
pub fn render_cookie_header(cookies: &[Cookie]) -> String {
    let mut seen_names = std::collections::HashSet::new();
    let cookie_parts: Vec<String> = cookies
        .iter()
        .rev() // Reverse to process most recent first
        .filter(|c| seen_names.insert(c.name.clone()))
        .map(|c| format!("{}={}", c.name, c.value))
        .collect::<Vec<_>>()
        .into_iter()
        .rev() // Reverse back to original order
        .collect();
    cookie_parts.join("; ")
}

pub fn output_cookies(cookies: &[Cookie], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Plain => {
            for cookie in cookies {
                println!("{}", cookie.value);
            }
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(cookies)?;
            println!("{}", json);
        }
        OutputFormat::Render => {
            println!("{}", render_cookie_header(cookies));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Cookie, CookieMeta};

    fn cookie(name: &str, value: &str) -> Cookie {
        Cookie {
            domain: ".example.com".to_string(),
            name: name.to_string(),
            value: value.to_string(),
            expiry: None,
            meta: CookieMeta {
                file: "/tmp/Cookies".to_string(),
                browser: "Chrome".to_string(),
                decrypted: true,
            },
        }
    }

    #[test]
    fn render_joins_name_value_pairs() {
        let cookies = vec![cookie("session", "abc"), cookie("user", "xyz")];
        assert_eq!(render_cookie_header(&cookies), "session=abc; user=xyz");
    }

    #[test]
    fn render_dedups_by_name_keeping_last_in_original_order() {
        // Two cookies share the name "session"; the later one wins, and the
        // surviving entries keep their original left-to-right order.
        let cookies = vec![
            cookie("session", "old"),
            cookie("user", "xyz"),
            cookie("session", "new"),
        ];
        assert_eq!(render_cookie_header(&cookies), "user=xyz; session=new");
    }

    #[test]
    fn render_empty_is_empty_string() {
        assert_eq!(render_cookie_header(&[]), "");
    }

    #[test]
    fn json_serialization_shape_includes_expected_fields() {
        let json = serde_json::to_value(cookie("session", "abc")).unwrap();
        assert_eq!(json["domain"], ".example.com");
        assert_eq!(json["name"], "session");
        assert_eq!(json["value"], "abc");
        assert_eq!(json["meta"]["browser"], "Chrome");
        assert_eq!(json["meta"]["decrypted"], true);
        assert_eq!(json["meta"]["file"], "/tmp/Cookies");
    }

    #[test]
    fn json_omits_expiry_when_absent() {
        // `expiry` uses skip_serializing_if = "Option::is_none".
        let json = serde_json::to_value(cookie("session", "abc")).unwrap();
        assert!(json.get("expiry").is_none());
    }
}
