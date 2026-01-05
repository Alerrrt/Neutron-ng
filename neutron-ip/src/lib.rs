use anyhow::Result;
use neutron_types::NetworkIntelligence;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIntelligence {
    pub ip: String,
    pub network_intel: NetworkIntelligence,
    pub geolocation: Option<Geolocation>,
    pub abuse_score: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Geolocation {
    pub country: String,
    pub city: String,
    pub lat: f64,
    pub lon: f64,
    pub isp: String,
}

/// Analyze an IP address
pub async fn analyze_ip(ip: &str) -> Result<IpIntelligence> {
    info!("Analyzing IP address: {}", ip);
    
    // 1. Get Network Intelligence (ASN, Reverse DNS, etc.)
    // We can reuse neutron-network logic but need to adapt it since 
    // neutron-network::gather_network_intel takes a domain.
    // For direct IP, we'll implement specific IP logic here or update neutron-network.
    // simpler to just call specific functions if they were public, 
    // but gather_network_intel is high level.
    
    // Let's manually trigger the sequence relevant for an IP
    
    // Reverse DNS
    let reverse_dns = get_reverse_dns(ip).await.unwrap_or_default();
    
    // ASN Info
    let asn = get_asn_info(ip).await.unwrap_or_default();
    
    // Geolocation
    let geo = get_geolocation(ip).await.ok();
    
    let intel = NetworkIntelligence {
        domain: ip.to_string(), // reusing field for IP
        asn_numbers: vec![asn],
        ip_ranges: vec![], // Harder from single IP without BGP lookup of ASN first
        reverse_dns: vec![reverse_dns],
        related_domains: vec![], // Could use reverse IP lookup here
    };
    
    Ok(IpIntelligence {
        ip: ip.to_string(),
        network_intel: intel,
        geolocation: geo,
        abuse_score: None, // Placeholder for Phase 17
    })
}

async fn get_reverse_dns(ip: &str) -> Result<String> {
    use std::process::Command;
    let output = Command::new("host").arg(ip).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = stdout.lines().find(|l| l.contains("pointer")) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(domain) = parts.last() {
            return Ok(domain.trim_end_matches('.').to_string());
        }
    }
    Ok(String::new())
}

async fn get_asn_info(ip: &str) -> Result<String> {
    // Basic wrapper, similar to neutron-network
    let client = reqwest::Client::new();
    let url = format!("https://ipinfo.io/{}/json", ip);
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(org) = json.get("org").and_then(|v| v.as_str()) {
                if let Some(asn) = org.split_whitespace().next() {
                    return Ok(asn.to_string());
                }
            }
        }
    }
    Ok(String::new())
}

async fn get_geolocation(ip: &str) -> Result<Geolocation> {
    use std::time::Duration;
    use tokio::time::sleep;
    
    let client = reqwest::Client::new();
    let url = format!("http://ip-api.com/json/{}", ip);
    
    // ip-api.com has a 45 req/min limit
    // Implement retry logic with exponential backoff
    let max_retries = 3;
    let mut retry_count = 0;
    
    loop {
        let resp = client.get(&url).send().await?;
        
        // Check for rate limiting (429 Too Many Requests)
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            if retry_count >= max_retries {
                return Err(anyhow::anyhow!(
                    "Rate limited by ip-api.com after {} retries. Please wait 1 minute.", 
                    max_retries
                ));
            }
            
            // Exponential backoff: 2^retry_count seconds
            let backoff = Duration::from_secs(2u64.pow(retry_count));
            tracing::warn!(
                "Rate limited by ip-api.com. Retrying in {} seconds... (attempt {}/{})",
                backoff.as_secs(),
                retry_count + 1,
                max_retries
            );
            sleep(backoff).await;
            retry_count += 1;
            continue;
        }
        
        // Parse response
        let json: serde_json::Value = resp.json().await?;
        
        // Validate response structure before accessing fields
        if json.get("status").is_none() {
            return Err(anyhow::anyhow!("Invalid API response format from ip-api.com"));
        }
        
        if json["status"].as_str() == Some("success") {
            return Ok(Geolocation {
                country: json["country"].as_str().unwrap_or_default().to_string(),
                city: json["city"].as_str().unwrap_or_default().to_string(),
                lat: json["lat"].as_f64().unwrap_or_default(),
                lon: json["lon"].as_f64().unwrap_or_default(),
                isp: json["isp"].as_str().unwrap_or_default().to_string(),
            });
        } else {
            // API returned an error (e.g., "fail" status)
            let message = json["message"].as_str().unwrap_or("Unknown error");
            return Err(anyhow::anyhow!("Geolocation failed: {}", message));
        }
    }
}
