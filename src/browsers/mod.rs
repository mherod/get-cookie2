pub mod chrome;
pub mod safari;
pub mod firefox;

use crate::types::{Cookie, CookieQuery};
use anyhow::Result;

pub trait BrowserCookieReader {
    fn find_cookie_stores(&self) -> Result<Vec<String>>;
    fn read_cookies(&self, store_path: &str, query: &CookieQuery) -> Result<Vec<Cookie>>;
}
