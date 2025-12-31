use anyhow::Result;
use neutron_core::HttpClient;
use scraper::{Html, Selector};

/// Fetch subdomains from RapidDNS.io
pub async fn fetch_rapiddns(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from RapidDNS for: {}", domain);
    
    let url = format!("https://rapiddns.io/subdomain/{}?full=1", domain);
    
    match client.get(&url).await {
        Ok(response) => {
            if response.status().is_success() {
                let html = response.text().await?;
                let document = Html::parse_document(&html);
                
                // RapidDNS displays subdomains in table rows
                let selector = Selector::parse("td").unwrap();
                
                let subdomains: Vec<String> = document
                    .select(&selector)
                    .filter_map(|element| {
                        let text = element.text().collect::<String>();
                        let trimmed = text.trim().to_lowercase();
                        if trimmed.ends_with(&domain) && trimmed.contains('.') {
                            Some(trimmed)
                        } else {
                            None
                        }
                    })
                    .collect();
                
                tracing::info!("RapidDNS found {} subdomains", subdomains.len());
                Ok(subdomains)
            } else {
                tracing::warn!("RapidDNS returned status: {}", response.status());
                Ok(vec![])
            }
        }
        Err(e) => {
            tracing::warn!("RapidDNS request failed: {}", e);
            Ok(vec![])
        }
    }
}
