use anyhow::Result;
use neutron_core::HttpClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CertShResult {
    name_value: String,
}

/// Fetch subdomains from cert.sh (certificate transparency logs)
pub async fn fetch_certsh(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from cert.sh for: {}", domain);
    
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    
    match client.get(&url).await {
        Ok(response) => {
            if response.status().is_success() {
                let text = response.text().await?;
                
                // Parse JSON response
                let entries: Vec<CertShResult> = serde_json::from_str(&text)
                    .unwrap_or_else(|_| vec![]);
                
                let subdomains: Vec<String> = entries
                    .into_iter()
                    .flat_map(|entry| {
                        // cert.sh can return multiple domains separated by newlines
                        entry.name_value
                            .split('\n')
                            .map(|s| s.trim().to_lowercase())
                            .filter(|s| s.ends_with(&domain))
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                    })
                    .collect();
                
                tracing::info!("cert.sh found {} subdomains", subdomains.len());
                Ok(subdomains)
            } else {
                tracing::warn!("cert.sh returned status: {}", response.status());
                Ok(vec![])
            }
        }
        Err(e) => {
            tracing::warn!("cert.sh request failed: {}", e);
            Ok(vec![])
        }
    }
}
