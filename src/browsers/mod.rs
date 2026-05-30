pub mod chrome;
pub mod firefox;
pub mod safari;

use crate::types::{Cookie, CookieQuery};
use anyhow::Result;

pub trait BrowserCookieReader {
    fn find_cookie_stores(&self) -> Result<Vec<String>>;
    fn read_cookies(&self, store_path: &str, query: &CookieQuery) -> Result<Vec<Cookie>>;
}
