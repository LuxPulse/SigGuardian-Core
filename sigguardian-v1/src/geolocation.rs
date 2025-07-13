use serde::Deserialize;
use reqwest::blocking::Client;
use std::time::Duration;
use crate::constants::GEOLOCATION_API;

#[derive(Debug, Deserialize, Clone)]
pub struct GeoData {
    pub ip: String,
    pub city: String,
    pub region: String,
    pub country: String,
    pub country_name: String,
    pub continent_code: String,
    pub postal: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: String,
    pub asn: String,
    pub org: String,
    pub threat_level: Option<String>,
}

pub fn get_geolocation() -> Option<GeoData> {
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;
        
    let response = client.get(GEOLOCATION_API)
        .header("User-Agent", "SigGuardian-X/1.0")
        .send()
        .ok()?;
        
    response.json().ok()
}