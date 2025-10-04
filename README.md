# get-cookie2

A fast, powerful command-line tool for extracting and using browser cookies. Built in Rust as a complete rewrite of the original Node.js `get-cookie` tool, with a focus on performance, security, and developer workflows.

## Features

- 🚀 **Extract cookies from multiple browsers**: Chrome, Firefox, Safari, Arc, Edge, Opera
- 🔐 **Decrypt Chrome cookies**: Seamless macOS Keychain integration with single permission prompt
- 🍪 **Multiple output formats**: Plain text, JSON, or HTTP Cookie header format
- 🔧 **JWT detection**: Automatically detect, decode, and validate JWT tokens in cookies
- ⚡ **Fast**: Written in Rust for maximum performance
- 🎯 **Developer-friendly**: Generate ready-to-use curl commands with `--curl` flag
- 📋 **Profile support**: List and access cookies from multiple browser profiles

## Installation

```bash
# Build from source
cargo build --release

# The binary will be at ./target/release/get-cookie2
# Optionally, copy to your PATH
cp ./target/release/get-cookie2 /usr/local/bin/
```

## Quick Start

```bash
# Extract specific cookie
get-cookie2 auth example.com

# Get all cookies for a domain as JSON
get-cookie2 % github.com --output json

# Generate and execute authenticated API request
get-cookie2 --url https://api.github.com/user --curl | bash

# Render cookies as HTTP header
get-cookie2 --url https://example.com -r
```

## Usage

```
get-cookie2 [OPTIONS] [NAME] [DOMAIN]

Arguments:
  [NAME]    Cookie name pattern (% for wildcard) [default: %]
  [DOMAIN]  Domain pattern [default: %]

Options:
  -b, --browser <BROWSER>        Browser to query (chrome, firefox, safari, arc, edge)
  -o, --output <OUTPUT>          Output format (plain, json, render)
  -u, --url <URL>                URL to extract domain from
  -r, --render                   Render as HTTP Cookie header format
      --curl                     Generate curl command with cookies inlined
  -j, --detect-jwt               Detect and decode JWT tokens
      --jwt-only                 Only show cookies containing JWTs
      --jwt-secret <SECRET>      Validate JWT signatures with secret
      --list-profiles            List available browser profiles
      --include-expired          Include expired cookies
  -v, --verbose                  Verbose output
  -h, --help                     Print help
```

## Examples

### Basic Cookie Extraction

```bash
# Extract a specific cookie by name and domain
get-cookie2 session_id example.com

# Extract all cookies for a domain
get-cookie2 % github.com

# Extract from a specific browser
get-cookie2 % example.com --browser firefox
```

### Working with URLs

```bash
# Extract cookies using a URL (extracts domain automatically)
get-cookie2 --url https://example.com/api/endpoint -r

# Output:
# session=abc123; user_id=xyz789; auth_token=...
```

### Authenticated API Requests

The `--curl` flag generates a complete curl command with cookies embedded:

```bash
# Generate curl command
get-cookie2 --url https://plugg.in/api/auth/whoami --curl

# Output:
# curl -s https://plugg.in/api/auth/whoami -H "Cookie: user_token=eyJhbG...; user_id=..."

# Execute immediately by piping to bash
get-cookie2 --url https://api.github.com/user --curl | bash

# Combine with jq for JSON processing
get-cookie2 --url https://api.example.com/data --curl | bash | jq .
```

### JWT Detection

```bash
# Detect and decode JWT tokens in cookies
get-cookie2 % example.com --detect-jwt

# Show only cookies containing JWTs
get-cookie2 % example.com --jwt-only

# Validate JWT signature with a secret
get-cookie2 % example.com --jwt-secret "your-secret-key"
```

### Browser Profiles

```bash
# List available Chrome profiles
get-cookie2 --list-profiles --browser chrome

# Output:
# Chrome profiles:
#
#   • Default
#     Directory: Default
#     User: user@example.com
#
#   • Work Profile
#     Directory: Profile 1
#     User: work@company.com
```

### JSON Output

```bash
# Get all cookies as JSON
get-cookie2 % example.com --output json | jq .

# Output:
# [
#   {
#     "domain": ".example.com",
#     "name": "session_id",
#     "value": "abc123xyz",
#     "expiry": "2025-12-31T23:59:59Z",
#     "meta": {
#       "file": "/Users/user/Library/Application Support/Google/Chrome/Default/Cookies",
#       "browser": "Chrome",
#       "decrypted": true
#     }
#   }
# ]
```

## Use Cases

### Testing APIs with Authentication

```bash
# Quick API testing with authenticated requests
get-cookie2 --url https://api.example.com/protected --curl | bash

# POST request with authentication
get-cookie2 --url https://api.example.com/data --curl | \
  sed 's/curl -s/curl -s -X POST -H "Content-Type: application\/json" -d "{}"/' | \
  bash
```

### Debugging Authentication Issues

```bash
# Check JWT token claims
get-cookie2 user_token example.com --detect-jwt

# Verify token expiration
get-cookie2 % example.com --jwt-only --output json | \
  jq '.[].value' -r | \
  while read token; do jwt decode "$token"; done
```

### Cookie Migration

```bash
# Export cookies from one browser to JSON
get-cookie2 % example.com --browser chrome --output json > cookies.json

# Import to another tool or use programmatically
```

## How It Works

### Chrome Cookie Decryption

`get-cookie2` handles Chrome's encrypted cookies seamlessly on macOS:

1. **Single Keychain Prompt**: Fetches the encryption key once and caches it globally
2. **AES-128-CBC Decryption**: Decrypts cookies using PBKDF2-HMAC-SHA1 key derivation
3. **Version Support**: Handles Chrome schema v24+ with 32-byte hash prefix stripping

### Cookie Deduplication

When cookies exist across multiple browser profiles:
- **Main deduplication**: By `(name, domain, value)` tuple to avoid identical duplicates
- **Render deduplication**: By `name` only to show single value per cookie in HTTP headers

## Platform Support

Currently supports **macOS** with plans to expand to other platforms:

- ✅ macOS (full support with Keychain integration)
- 🔜 Linux (planned)
- 🔜 Windows (planned)

## Development

```bash
# Build for development
cargo build

# Build optimized release binary
cargo build --release

# Run tests
cargo test

# Run with verbose output
cargo run -- % example.com -v
```

## Architecture

- **Modular browser readers**: Each browser has its own module implementing `BrowserCookieReader` trait
- **Global caching**: Chrome encryption key cached to minimize Keychain prompts
- **SQLite access**: Temporary file copying to avoid database locks
- **JWT support**: Built-in JWT detection, decoding, and validation

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation.

## Security Considerations

- **Read-only**: Only reads browser cookie databases, never modifies them
- **Temporary files**: Copies databases to `/tmp` for safe access
- **Keychain integration**: Uses system Keychain on macOS (requires user approval)
- **No network access**: All operations are local

⚠️ **Important**: Cookies are sensitive credentials. Be careful when:
- Sharing `--curl` output (contains authentication tokens)
- Storing JSON exports (may contain session data)
- Using in scripts (ensure proper access controls)

## Troubleshooting

### Permission Denied on Keychain

If you get repeated Keychain permission prompts:
- Click "Always Allow" when prompted
- The key is cached globally after first access

### No Cookies Found

- Ensure the browser is closed or not actively using the database
- Try with `--verbose` to see what's being searched
- Check the domain pattern matches (use `%` as wildcard)

### Database Locked Errors

- Close the browser and try again
- The tool copies databases to temp files to avoid locks, but active writes can still cause issues

## Contributing

Contributions are welcome! Areas for improvement:
- Linux and Windows support
- Additional browser support (Brave, Vivaldi, etc.)
- Safari cookie decryption
- More output formats
- Performance optimizations

## License

[Add your license here]

## Acknowledgments

- Original Node.js `get-cookie` tool for inspiration
- Rust community for excellent libraries
- [Chromium source](https://chromium.googlesource.com/chromium/src/+/b02dcebd7cafab92770734dc2bc317bd07f1d891/net/extras/sqlite/sqlite_persistent_cookie_store.cc#223) for cookie encryption documentation
