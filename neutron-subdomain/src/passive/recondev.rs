use anyhow::Result;
use neutron_core::HttpClient;

/// Fetch subdomains from recon.dev
pub async fn fetch_recondev(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from recon.dev for: {}", domain);
    
    let url = format!("https://recon.dev/api/search?domain={}", domain);
    
    match client.get(&url).await {
        Ok(response) => {
            if response.status().is_success() {
                let text = response.text().await?;
                
                // recon.dev returns JSON array of subdomains
                let subdomains: Vec<String> = serde_json::from_str(&text)
                    .unwrap_or_else(|_| vec![]);
                
                let filtered: Vec<String> = subdomains
                    .into_iter()
                    .map(|s| s.to_lowercase())
                    .filter(|s| s.ends_with(&domain))
                    .collect();
                
                tracing::info!("recon.dev found {} subdomains", filtered.len());
                Ok(filtered)
            } else {
                tracing::warn!("recon.dev returned status: {}", response.status());
                Ok(vec![])
            }
        }
        Err(e) => {
            tracing::warn!("recon.dev request failed: {}", e);
            Ok(vec![])
        }
    }
}
