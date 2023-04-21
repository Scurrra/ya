//! Separate module to obtain public IP.
//! 
//! Notes:
//!  - currently only IPv4
//!  - uses [ifconfig](https://ifconfig.me)
//!  - may be async in future and use hyper directly

use std::{net::Ipv4Addr, str::FromStr};

#[cfg(feature = "reqwest")]
use reqwest;

#[cfg(feature = "ureq")]
use ureq;

#[cfg(feature = "isahc")]
use isahc::prelude::*;
#[cfg(feature = "isahc")]
fn isahc_get_string() -> Result<String, isahc::Error> {
    let resp = isahc::get("https://ifconfig.me/ip")?.text()?;
    return Ok(resp)
}

#[cfg(feature = "reqwest")]
/// Function to obtain IPv4 address from `ifconfig.me`
pub fn obtain_ipv4_addr() -> Option<Ipv4Addr> {
    let resp = reqwest::blocking::get("https://ifconfig.me/ip").ok();
    if let Some(resp) = resp {
        if let Ok(resp) = resp.text() {
            return Ipv4Addr::from_str(&resp).ok();
        }
    }
    None
}

#[cfg(feature = "ureq")]
/// Function to obtain IPv4 address from `ifconfig.me`
pub fn obtain_ipv4_addr() -> Option<Ipv4Addr> {
    let resp = ureq::get("http://ifconfig.me/ip").call().ok();
    if let Some(resp) = resp {
        if let Ok(resp) = resp.into_string() {
            return Ipv4Addr::from_str(&resp).ok();
        }
    }
    None
}

#[cfg(feature = "isahc")]
/// Function to obtain IPv4 address from `ifconfig.me`
pub fn obtain_ipv4_addr() -> Option<Ipv4Addr> {
    let resp = isahc_get_string();
    if let Ok(resp) = resp {
        return Ipv4Addr::from_str(&resp).ok();
    }
    None
}