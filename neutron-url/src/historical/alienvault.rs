use anyhow::Result;
use neutron_core::HttpClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AlienVaultResponse {
    url_list: Vec<UrlEntry>,
}

#[derive(Debug, Deserialize)]
struct UrlEntry {
    url: String,
}

/// Fetch URLs from AlienVault OTX
pub async fn fetch_alienvault(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from AlienVault OTX for: {}", domain);
    
    let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list", domain);
    
    match client.get(&url).await {
        Ok(response) => {
            if response.status().is_success() {
                let av_response: AlienVaultResponse = response.json().await?;
                
                let urls: Vec<String> = av_response.url_list
                    .into_iter()
                    .map(|entry| entry.url)
                    .filter(|url| url.contains(&domain))
                    .collect();
                
                tracing::info!("AlienVault OTX found {} URLs", urls.len());
                Ok(urls)
            } else {
                tracing::warn!("AlienVault OTX returned status: {}", response.status());
                Ok(vec![])
            }
        }
        Err(e) => {
            tracing::warn!("AlienVault OTX request failed: {}", e);
            Ok(vec![])
        }
    }
}
