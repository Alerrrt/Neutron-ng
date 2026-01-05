use anyhow::Result;
use neutron_core::HttpClient;

/// Fetch subdomains from ip.thc.org (The Hacker's Choice)
pub async fn fetch_thc(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching subdomains from ip.thc.org for: {}", domain);
    
    // THC subdomain finder endpoint
    let url = format!("https://ip.thc.org/sub/{}", domain);
    
    let response = client.get(&url).await?;
    
    if !response.status().is_success() {
        anyhow::bail!("ip.thc.org returned status: {}", response.status());
    }
    
    let text = response.text().await?;
    
    // THC returns results in HTML format, we need to extract subdomains
    // Looking for patterns like: subdomain.example.com
    let subdomains: Vec<String> = text
        .lines()
        .filter_map(|line| {
            // Extract domain-like patterns from the HTML
            if line.contains(&domain) {
                // Try to extract the full subdomain
                if let Some(start) = line.find("http") {
                    if let Some(end) = line[start..].find("\"") {
                        let url_part = &line[start..start + end];
                        if let Some(domain_start) = url_part.find("://") {
                            let full_domain = &url_part[domain_start + 3..];
                            if let Some(slash_pos) = full_domain.find('/') {
                                return Some(full_domain[..slash_pos].to_string());
                            }
                            return Some(full_domain.to_string());
                        }
                    }
                }
            }
            None
        })
        .filter(|subdomain| subdomain.ends_with(&format!(".{}", domain)) || subdomain == &domain)
        .collect();
    
    tracing::debug!("ip.thc.org found {} subdomains", subdomains.len());
    Ok(subdomains)
}
