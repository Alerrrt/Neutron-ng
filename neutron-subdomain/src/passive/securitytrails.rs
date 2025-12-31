use anyhow::Result;
use neutron_core::HttpClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SecurityTrailsResponse {
    subdomains: Vec<String>,
}

/// Fetch subdomains from SecurityTrails API
pub async fn fetch_securitytrails(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from SecurityTrails for: {}", domain);
    
    let api_key = match std::env::var("NEUTRON_SECURITYTRAILS_API_KEY") {
        Ok(key) => key,
        Err(_) => {
            tracing::debug!("SecurityTrails API key not found, skipping");
            return Ok(vec![]);
        }
    };
    
    let url = format!("https://api.securitytrails.com/v1/domain/{}/subdomains", domain);
    
    let response = client.client()
        .get(&url)
        .header("apikey", api_key)
        .send()
        .await?;
    
    if response.status().is_success() {
        let st_response: SecurityTrailsResponse = response.json().await?;
        
        // SecurityTrails returns subdomain prefixes, we need to append the domain
        let subdomains: Vec<String> = st_response
            .subdomains
            .into_iter()
            .map(|prefix| format!("{}.{}", prefix, domain).to_lowercase())
            .collect();
        
        tracing::info!("SecurityTrails found {} subdomains", subdomains.len());
        Ok(subdomains)
    } else {
        tracing::warn!("SecurityTrails returned status: {}", response.status());
        Ok(vec![])
    }
}
