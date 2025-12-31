use anyhow::Result;
use neutron_core::HttpClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VirusTotalResponse {
    data: Vec<VirusTotalSubdomain>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalSubdomain {
    id: String,
}

/// Fetch subdomains from VirusTotal API
pub async fn fetch_virustotal(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from VirusTotal for: {}", domain);
    
    // Check for API key in environment
    let api_key = match std::env::var("NEUTRON_VIRUSTOTAL_API_KEY") {
        Ok(key) => key,
        Err(_) => {
            tracing::debug!("VirusTotal API key not found, skipping");
            return Ok(vec![]);
        }
    };
    
    let url = format!("https://www.virustotal.com/api/v3/domains/{}/subdomains", domain);
    
    let response = client.client()
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await?;
    
    if response.status().is_success() {
        let vt_response: VirusTotalResponse = response.json().await?;
        
        let subdomains: Vec<String> = vt_response
            .data
            .into_iter()
            .map(|s| s.id.to_lowercase())
            .filter(|s| s.ends_with(&domain))
            .collect();
        
        tracing::info!("VirusTotal found {} subdomains", subdomains.len());
        Ok(subdomains)
    } else {
        tracing::warn!("VirusTotal returned status: {}", response.status());
        Ok(vec![])
    }
}
