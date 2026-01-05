use anyhow::Result;
use neutron_core::HttpClient;

/// Fetch subdomains from subdomain.center
pub async fn fetch_subdomaincenter(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching subdomains from subdomain.center for: {}", domain);
    
    // subdomain.center API endpoint
    let url = format!("https://api.subdomain.center/?domain={}", domain);
    
    let response = client.get(&url).await?;
    
    if !response.status().is_success() {
        anyhow::bail!("subdomain.center returned status: {}", response.status());
    }
    
    let text = response.text().await?;
    
    // subdomain.center returns one subdomain per line
    let subdomains: Vec<String> = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.trim().to_string())
        .filter(|subdomain| subdomain.ends_with(&format!(".{}", domain)) || subdomain == &domain)
        .collect();
    
    tracing::debug!("subdomain.center found {} subdomains", subdomains.len());
    Ok(subdomains)
}
