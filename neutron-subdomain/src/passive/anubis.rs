use anyhow::Result;
use neutron_core::HttpClient;

/// Fetch subdomains from Anubis (jldc.me)
pub async fn fetch_anubis(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from Anubis for: {}", domain);
    
    let url = format!("https://jldc.me/anubis/subdomains/{}", domain);
    
    match client.get(&url).await {
        Ok(response) => {
            if response.status().is_success() {
                let subdomains: Vec<String> = response.json().await?;
                
                let filtered: Vec<String> = subdomains
                    .into_iter()
                    .map(|s| s.to_lowercase())
                    .filter(|s| s.ends_with(&domain))
                    .collect();
                
                tracing::info!("Anubis found {} subdomains", filtered.len());
                Ok(filtered)
            } else {
                tracing::warn!("Anubis returned status: {}", response.status());
                Ok(vec![])
            }
        }
        Err(e) => {
            tracing::warn!("Anubis request failed: {}", e);
            Ok(vec![])
        }
    }
}
