use anyhow::Result;
use neutron_core::HttpClient;

/// Fetch subdomains from Project Discovery Chaos dataset
pub async fn fetch_chaos(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from Chaos for: {}", domain);
    
    let api_key = match std::env::var("NEUTRON_CHAOS_API_KEY") {
        Ok(key) => key,
        Err(_) => {
            tracing::debug!("Chaos API key not found, skipping");
            return Ok(vec![]);
        }
    };
    
    let url = format!("https://dns.projectdiscovery.io/dns/{}/subdomains", domain);
    
    let response = client.client()
        .get(&url)
        .header("Authorization", api_key)
        .send()
        .await?;
    
    if response.status().is_success() {
        let text = response.text().await?;
        
        // Chaos returns one subdomain per line
        let subdomains: Vec<String> = text
            .lines()
            .map(|line| line.trim().to_lowercase())
            .filter(|line| !line.is_empty() && line.ends_with(&domain))
            .collect();
        
        tracing::info!("Chaos found {} subdomains", subdomains.len());
        Ok(subdomains)
    } else {
        tracing::warn!("Chaos returned status: {}", response.status());
        Ok(vec![])
    }
}
