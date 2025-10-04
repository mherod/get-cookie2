use crate::types::Cookie;
use anyhow::Result;
use serde_json;

pub enum OutputFormat {
    Plain,
    Json,
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
    }

    Ok(())
}
