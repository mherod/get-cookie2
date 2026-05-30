mod browsers;
mod crypto;
mod jwt;
mod output;
mod types;

use anyhow::{Context, Result};
use browsers::{chrome::ChromeCookieReader, firefox::FirefoxCookieReader, BrowserCookieReader};
use clap::Parser;
use output::{output_cookies, OutputFormat};
use types::{Browser, CookieQuery};

#[derive(Parser, Debug)]
#[command(name = "get-cookie2")]
#[command(about = "Extract cookies from browser databases")]
#[command(long_about = None)]
#[command(after_help = "\
EXAMPLES:
    # Extract specific cookie
    get-cookie2 auth example.com

    # Get all cookies for a domain as JSON
    get-cookie2 % github.com --output json

    # Render cookies as HTTP Cookie header
    get-cookie2 --url https://example.com -r

    # Generate and execute authenticated curl request
    get-cookie2 --url https://api.example.com/endpoint --curl | bash

    # Detect and decode JWT tokens in cookies
    get-cookie2 % example.com --detect-jwt

    # List browser profiles
    get-cookie2 --list-profiles --browser chrome

WORKFLOW TIPS:
    The --curl flag generates a ready-to-use curl command with cookies inlined.
    Pipe the output to 'bash' to execute immediately, or copy/paste for later use.

    Example workflow:
      get-cookie2 --url https://api.github.com/user --curl | bash | jq .
")]
struct Args {
    /// Cookie name pattern (% for wildcard)
    #[arg(default_value = "%")]
    name: String,

    /// Domain pattern
    #[arg(default_value = "%")]
    domain: String,

    /// Browser to query (chrome, firefox, safari, arc, edge)
    #[arg(short, long)]
    browser: Option<String>,

    /// Output format (plain, json, render)
    #[arg(short, long, default_value = "plain")]
    output: String,

    /// URL to extract domain from (extracts cookies for the base domain)
    #[arg(short, long)]
    url: Option<String>,

    /// Render cookies as HTTP Cookie header format (name=value; name=value)
    #[arg(short, long)]
    render: bool,

    /// Include expired cookies
    #[arg(long)]
    include_expired: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Detect and decode JWT tokens
    #[arg(short = 'j', long)]
    detect_jwt: bool,

    /// Only show cookies containing JWTs
    #[arg(long)]
    jwt_only: bool,

    /// Validate JWT signatures with secret
    #[arg(long)]
    jwt_secret: Option<String>,

    /// List available browser profiles
    #[arg(long)]
    list_profiles: bool,

    /// Generate curl command with cookies inlined (use with --url, pipe to bash to execute)
    #[arg(long)]
    curl: bool,
}

fn list_profiles(browser_name: &str) -> Result<()> {
    use std::fs;

    let home = dirs::home_dir().expect("Failed to get home directory");

    let (base_path, name) = match browser_name {
        "chrome" => (
            home.join("Library/Application Support/Google/Chrome"),
            "Chrome",
        ),
        "arc" => (home.join("Library/Application Support/Arc"), "Arc"),
        "edge" => (
            home.join("Library/Application Support/Microsoft Edge"),
            "Edge",
        ),
        "firefox" => (
            home.join("Library/Application Support/Firefox/Profiles"),
            "Firefox",
        ),
        _ => {
            eprintln!("Profile listing not supported for {}", browser_name);
            return Ok(());
        }
    };

    if !base_path.exists() {
        eprintln!("{} not found", name);
        return Ok(());
    }

    println!("{} profiles:\n", name);

    if browser_name == "firefox" {
        // Firefox profiles
        for entry in fs::read_dir(&base_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name() {
                    println!("  • {}", name.to_string_lossy());
                    println!("    Directory: {}", path.display());
                    println!();
                }
            }
        }
    } else {
        // Chromium-based browsers
        let default_path = base_path.join("Default");
        if default_path.exists() {
            println!("  • Default");
            println!("    Directory: Default");

            // Try to get user email from "Preferences" file
            let prefs_path = default_path.join("Preferences");
            if let Ok(prefs) = fs::read_to_string(&prefs_path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&prefs) {
                    if let Some(email) = json["account_info"][0]["email"].as_str() {
                        println!("    User: {}", email);
                    }
                }
            }
            println!();
        }

        // Additional profiles
        for entry in fs::read_dir(&base_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                if let Some(dir_name) = path.file_name() {
                    let dir_str = dir_name.to_string_lossy();
                    if dir_str.starts_with("Profile ") {
                        // Try to get profile name from Preferences
                        let prefs_path = path.join("Preferences");
                        let mut profile_name = dir_str.to_string();

                        if let Ok(prefs) = fs::read_to_string(&prefs_path) {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&prefs) {
                                if let Some(name) = json["profile"]["name"].as_str() {
                                    profile_name = name.to_string();
                                }
                            }
                        }

                        println!("  • {}", profile_name);
                        println!("    Directory: {}", dir_str);

                        // Try to get user email
                        if let Ok(prefs) = fs::read_to_string(&prefs_path) {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&prefs) {
                                if let Some(email) = json["account_info"][0]["email"].as_str() {
                                    println!("    User: {}", email);
                                }
                            }
                        }
                        println!();
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    // Show help if no arguments provided
    if std::env::args().len() == 1 {
        Args::parse_from(["get-cookie2", "--help"]);
    }

    let args = Args::parse();

    // Handle profile listing
    if args.list_profiles {
        let browser_name = args.browser.as_deref().unwrap_or("chrome");
        return list_profiles(browser_name);
    }

    // Handle curl command generation - we'll process this after collecting cookies
    let curl_mode = args.curl;

    // Extract domain from URL if provided
    let domain_pattern = if let Some(ref url_str) = args.url {
        let parsed_url = url::Url::parse(url_str).context("Failed to parse URL")?;

        let domain = parsed_url.host_str().context("URL has no host")?;

        // Use % wildcards to match subdomains
        format!("%{}%", domain)
    } else {
        args.domain.clone()
    };

    let browser = match args.browser.as_deref() {
        Some("chrome") => Some(Browser::Chrome),
        Some("firefox") => Some(Browser::Firefox),
        Some("safari") => Some(Browser::Safari),
        Some("arc") => Some(Browser::Arc),
        Some("edge") => Some(Browser::Edge),
        Some("opera") => Some(Browser::Opera),
        None => None,
        Some(other) => {
            eprintln!("Unknown browser: {}", other);
            std::process::exit(1);
        }
    };

    let query = CookieQuery {
        name_pattern: args.name.clone(),
        domain_pattern: Some(domain_pattern),
        include_expired: args.include_expired,
    };

    let output_format = if args.render || args.output == "render" {
        OutputFormat::Render
    } else {
        match args.output.as_str() {
            "json" => OutputFormat::Json,
            "plain" => OutputFormat::Plain,
            "render" => OutputFormat::Render,
            _ => {
                eprintln!("Unknown output format: {}", args.output);
                std::process::exit(1);
            }
        }
    };

    let mut all_cookies = Vec::new();

    // Determine which browsers to query
    let browsers_to_query: Vec<Browser> = if let Some(b) = browser {
        vec![b]
    } else {
        vec![
            Browser::Chrome,
            Browser::Firefox,
            Browser::Arc,
            Browser::Edge,
        ]
    };

    for browser in browsers_to_query {
        let reader: Box<dyn BrowserCookieReader> = match browser {
            Browser::Chrome | Browser::Arc | Browser::Edge => {
                Box::new(ChromeCookieReader::new(browser))
            }
            Browser::Firefox => Box::new(FirefoxCookieReader::new()),
            Browser::Safari => {
                // Safari stores cookies in the binary Cookies.binarycookies format,
                // which is not yet parsed. Tell the user rather than silently skipping.
                eprintln!(
                    "Safari cookie extraction is not yet implemented (binary Cookies.binarycookies format). Skipping."
                );
                continue;
            }
            Browser::Opera => {
                eprintln!("Opera cookie extraction is not yet implemented. Skipping.");
                continue;
            }
        };

        if args.verbose {
            eprintln!("Searching {} cookies...", browser.as_str());
        }

        match reader.find_cookie_stores() {
            Ok(stores) => {
                for store in stores {
                    if args.verbose {
                        eprintln!("  Reading from: {}", store);
                    }

                    match reader.read_cookies(&store, &query) {
                        Ok(cookies) => {
                            if args.verbose {
                                eprintln!("    Found {} cookies", cookies.len());
                            }
                            all_cookies.extend(cookies);
                        }
                        Err(e) => {
                            if args.verbose {
                                eprintln!("    Error reading cookies: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("  Error finding cookie stores: {}", e);
                }
            }
        }
    }

    // Deduplicate cookies by (name, domain, value) tuple
    // This prevents showing the same cookie multiple times when it exists
    // across different browser profiles
    let mut seen = std::collections::HashSet::new();
    all_cookies.retain(|cookie| {
        seen.insert((
            cookie.name.clone(),
            cookie.domain.clone(),
            cookie.value.clone(),
        ))
    });

    // Filter for JWTs if requested
    if args.jwt_only {
        all_cookies.retain(|cookie| jwt::is_jwt(&cookie.value));
    }

    // Detect and decode JWTs if requested
    if args.detect_jwt || args.jwt_secret.is_some() {
        for cookie in &all_cookies {
            if jwt::is_jwt(&cookie.value) {
                if args.verbose {
                    eprintln!(
                        "\nJWT detected in cookie '{}' from {}",
                        cookie.name, cookie.domain
                    );
                }

                if let Some(ref secret) = args.jwt_secret {
                    if let Some(jwt_info) = jwt::validate_jwt(&cookie.value, secret) {
                        eprintln!("\n✓ JWT signature valid for '{}'", cookie.name);
                        eprintln!(
                            "  Header: {}",
                            serde_json::to_string_pretty(&jwt_info.header)?
                        );
                        eprintln!(
                            "  Claims: {}",
                            serde_json::to_string_pretty(&jwt_info.claims)?
                        );
                    } else {
                        eprintln!("\n✗ JWT signature invalid for '{}'", cookie.name);
                    }
                } else if let Some(jwt_info) = jwt::decode_jwt(&cookie.value) {
                    if args.verbose || args.detect_jwt {
                        eprintln!(
                            "  Header: {}",
                            serde_json::to_string_pretty(&jwt_info.header)?
                        );
                        eprintln!(
                            "  Claims: {}",
                            serde_json::to_string_pretty(&jwt_info.claims)?
                        );
                    }
                }
            }
        }
    }

    // Handle curl mode - inline cookies into curl command
    if curl_mode {
        if args.url.is_none() {
            eprintln!("Error: --curl requires --url to be specified");
            std::process::exit(1);
        }
        let url_str = args.url.as_ref().unwrap();

        // Generate cookie header from collected cookies (shared dedup-by-name
        // logic with the Render output format).
        let cookie_str = output::render_cookie_header(&all_cookies);

        let cmd = format!("curl -s {} -H \"Cookie: {}\"", url_str, cookie_str);
        println!("{}", cmd);
    } else {
        output_cookies(&all_cookies, output_format)?;
    }

    Ok(())
}
