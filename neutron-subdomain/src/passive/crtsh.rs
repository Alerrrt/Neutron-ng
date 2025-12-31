use anyhow::Result;
use neutron_core::HttpClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

/// Fetch subdomains from crt.sh (alternative endpoint)
pub async fn fetch_crtsh(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from crt.sh for: {}", domain);
    
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    
    match client.get(&url).await {
        Ok(response) => {
            if response.status().is_success() {
                let text = response.text().await?;
                
                let entries: Vec<CrtShEntry> = serde_json::from_str(&text)
                    .unwrap_or_else(|_| vec![]);
                
                let subdomains: Vec<String> = entries
                    .into_iter()
                    .flat_map(|entry| {
                        entry.name_value
                            .split('\n')
                            .map(|s| s.trim().to_lowercase())
                            .filter(|s| s.ends_with(&domain) && !s.starts_with('*'))
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                    })
                    .collect();
                
                tracing::info!("crt.sh found {} subdomains", subdomains.len());
                Ok(subdomains)
            } else {
                Ok(vec![])
            }
        }
        Err(e) => {
            tracing::warn!("crt.sh request failed: {}", e);
            Ok(vec![])
        }
    }
}
