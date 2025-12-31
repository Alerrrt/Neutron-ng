use anyhow::Result;
use neutron_core::HttpClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct BufferOverResponse {
    #[serde(rename = "FDNS_A")]
    fdns_a: Option<Vec<String>>,
}

/// Fetch subdomains from BufferOver.run
pub async fn fetch_bufferover(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from BufferOver for: {}", domain);
    
    let url = format!("https://dns.bufferover.run/dns?q=.{}", domain);
    
    match client.get(&url).await {
        Ok(response) => {
            if response.status().is_success() {
                let buffer_response: BufferOverResponse = response.json().await?;
                
                let subdomains: Vec<String> = buffer_response
                    .fdns_a
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|entry| {
                        // BufferOver format: "subdomain,ip"
                        entry.split(',').next().map(|s| s.trim().to_lowercase())
                    })
                    .filter(|s| s.ends_with(&domain))
                    .collect();
                
                tracing::info!("BufferOver found {} subdomains", subdomains.len());
                Ok(subdomains)
            } else {
                tracing::warn!("BufferOver returned status: {}", response.status());
                Ok(vec![])
            }
        }
        Err(e) => {
            tracing::warn!("BufferOver request failed: {}", e);
            Ok(vec![])
        }
    }
}
