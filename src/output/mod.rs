use crate::types::Cookie;
use anyhow::Result;

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
            // Deduplicate by name, keeping the most recent (last) cookie
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
            println!("{}", cookie_parts.join("; "));
        }
    }

    Ok(())
}
