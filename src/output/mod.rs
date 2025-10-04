use crate::types::Cookie;
use anyhow::Result;
use serde_json;

pub enum OutputFormat {
    Plain,
    Json,
    Render,
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
            // Output as HTTP Cookie header format: name=value; name=value
            let cookie_parts: Vec<String> = cookies
                .iter()
                .map(|c| format!("{}={}", c.name, c.value))
                .collect();
            println!("{}", cookie_parts.join("; "));
        }
    }

    Ok(())
}
