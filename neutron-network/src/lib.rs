use anyhow::{Result, Context};
use neutron_types::NetworkIntelligence;
use regex::Regex;
use tracing::{info, warn};

/// Perform comprehensive network intelligence gathering
pub async fn gather_network_intel(domain: &str) -> Result<NetworkIntelligence> {
    info!("Gathering network intelligence for: {}", domain);
    
    let mut intel = NetworkIntelligence {
        domain: domain.to_string(),
        asn_numbers: Vec::new(),
        ip_ranges: Vec::new(),
        reverse_dns: Vec::new(),
        related_domains: Vec::new(),
    };
    
    // Get IP address first
    if let Ok(ips) = get_ip_addresses(domain).await {
        info!("Found {} IP addresses", ips.len());
        
        // For each IP, get ASN and reverse DNS
        for ip in &ips {
            // Get ASN information
            if let Ok(asn_info) = get_asn_info(ip).await {
                if !intel.asn_numbers.contains(&asn_info) {
                    intel.asn_numbers.push(asn_info);
                }
            }
            
            // Get reverse DNS
            if let Ok(ptr) = get_reverse_dns(ip).await {
                intel.reverse_dns.push(format!("{} -> {}", ip, ptr));
            }
        }
        
        // Get IP ranges from ASN
        for asn in &intel.asn_numbers {
            if let Ok(ranges) = get_ip_ranges_from_asn(asn).await {
                intel.ip_ranges.extend(ranges);
            }
        }
    }
    
    info!("Network intelligence gathering complete");
    Ok(intel)
}

/// Get IP addresses for a domain
async fn get_ip_addresses(domain: &str) -> Result<Vec<String>> {
    use std::process::Command;
    
    let output = Command::new("host")
        .arg(domain)
        .output()
        .context("Failed to execute host command")?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ip_regex = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
    
    let ips: Vec<String> = ip_regex
        .find_iter(&stdout)
        .map(|m| m.as_str().to_string())
        .collect();
    
    Ok(ips)
}

/// Get ASN information for an IP address
async fn get_asn_info(ip: &str) -> Result<String> {
    info!("Looking up ASN for IP: {}", ip);
    
    // Try ipinfo.io first
    let client = reqwest::Client::new();
    let url = format!("https://ipinfo.io/{}/json", ip);
    
    match client.get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(response) => {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if let Some(org) = json.get("org").and_then(|v| v.as_str()) {
                    // Format: "AS15169 Google LLC"
                    if let Some(asn) = org.split_whitespace().next() {
                        if asn.starts_with("AS") {
                            return Ok(asn.to_string());
                        }
                    }
                }
            }
        }
        Err(e) => {
            warn!("ipinfo.io lookup failed: {}", e);
        }
    }
    
    // Fallback to whois
    use std::process::Command;
    let output = Command::new("whois")
        .arg(ip)
        .output();
    
    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let asn_regex = Regex::new(r"AS(\d+)").unwrap();
        
        if let Some(capture) = asn_regex.captures(&stdout) {
            if let Some(asn) = capture.get(0) {
                return Ok(asn.as_str().to_string());
            }
        }
    }
    
    Err(anyhow::anyhow!("Could not determine ASN for {}", ip))
}

/// Get reverse DNS (PTR record) for an IP
async fn get_reverse_dns(ip: &str) -> Result<String> {
    use std::process::Command;
    
    let output = Command::new("host")
        .arg(ip)
        .output()
        .context("Failed to execute host command")?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Look for "domain name pointer"
    if let Some(line) = stdout.lines().find(|l| l.contains("pointer")) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(domain) = parts.last() {
            return Ok(domain.trim_end_matches('.').to_string());
        }
    }
    
    Err(anyhow::anyhow!("No PTR record found for {}", ip))
}

/// Get IP ranges from ASN number
async fn get_ip_ranges_from_asn(asn: &str) -> Result<Vec<String>> {
    info!("Getting IP ranges for ASN: {}", asn);
    
    // Remove "AS" prefix if present
    let asn_num = asn.trim_start_matches("AS");
    
    let client = reqwest::Client::new();
    let url = format!("https://api.bgpview.io/asn/{}/prefixes", asn_num);
    
    match client.get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                let mut ranges = Vec::new();
                
                // Get IPv4 prefixes
                if let Some(ipv4) = json.get("data").and_then(|d| d.get("ipv4_prefixes")) {
                    if let Some(prefixes) = ipv4.as_array() {
                        for prefix in prefixes {
                            if let Some(cidr) = prefix.get("prefix").and_then(|p| p.as_str()) {
                                ranges.push(cidr.to_string());
                            }
                        }
                    }
                }
                
                // Get IPv6 prefixes
                if let Some(ipv6) = json.get("data").and_then(|d| d.get("ipv6_prefixes")) {
                    if let Some(prefixes) = ipv6.as_array() {
                        for prefix in prefixes {
                            if let Some(cidr) = prefix.get("prefix").and_then(|p| p.as_str()) {
                                ranges.push(cidr.to_string());
                            }
                        }
                    }
                }
                
                info!("Found {} IP ranges for {}", ranges.len(), asn);
                return Ok(ranges);
            }
        }
        Err(e) => {
            warn!("BGPView API failed: {}", e);
        }
    }
    
    Ok(Vec::new())
}

/// Perform reverse IP lookup to find other domains on same server
pub async fn reverse_ip_lookup(ip: &str) -> Result<Vec<String>> {
    info!("Performing reverse IP lookup for: {}", ip);
    
    let client = reqwest::Client::new();
    let url = format!("https://api.hackertarget.com/reverseiplookup/?q={}", ip);
    
    match client.get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            if let Ok(text) = response.text().await {
                let domains: Vec<String> = text
                    .lines()
                    .filter(|line| !line.contains("error") && !line.is_empty())
                    .map(|s| s.trim().to_string())
                    .collect();
                
                info!("Found {} domains on same IP", domains.len());
                return Ok(domains);
            }
        }
        Err(e) => {
            warn!("Reverse IP lookup failed: {}", e);
        }
    }
    
    Ok(Vec::new())
}
