pub mod wayback;
pub mod commoncrawl;
pub mod alienvault;
pub mod urlscan;

use anyhow::Result;
use neutron_core::HttpClient;
use neutron_types::UrlResult;
use std::collections::HashSet;

/// Discover URLs from historical sources
pub async fn discover_historical(domain: &str) -> Result<Vec<UrlResult>> {
    tracing::info!("Starting historical URL discovery for: {}", domain);
    
    let http_client = HttpClient::new(
        std::time::Duration::from_secs(30),
        None,
        format!("Neutron-ng/{}", env!("CARGO_PKG_VERSION")),
        50, // Lower rate limit for historical sources
    )?;
    
    let mut all_urls = HashSet::new();
    let mut results = Vec::new();
    
    // Run all historical sources concurrently
    let domain_clone = domain.to_string();
    let sources = vec![
        tokio::spawn(wayback::fetch_wayback(domain_clone.clone(), http_client.clone())),
        tokio::spawn(commoncrawl::fetch_commoncrawl(domain_clone.clone(), http_client.clone())),
        tokio::spawn(alienvault::fetch_alienvault(domain_clone.clone(), http_client.clone())),
        tokio::spawn(urlscan::fetch_urlscan(domain_clone.clone(), http_client.clone())),
    ];
    
    let source_names = vec!["Wayback Machine", "Common Crawl", "AlienVault OTX", "URLScan.io"];
    
    // Collect results from all sources
    for (idx, source) in sources.into_iter().enumerate() {
        let source_name = source_names.get(idx).unwrap_or(&"unknown");
        match source.await {
            Ok(Ok(urls)) => {
                tracing::info!("{} found {} URLs", source_name, urls.len());
                for url in urls {
                    if all_urls.insert(url.clone()) {
                        results.push(UrlResult {
                            url,
                            source: source_name.to_string(),
                            status_code: None,
                            content_type: None,
                        });
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::warn!("{} failed: {}", source_name, e);
            }
            Err(e) => {
                tracing::warn!("{} task failed: {}", source_name, e);
            }
        }
    }
    
    tracing::info!("Historical discovery found {} unique URLs", results.len());
    Ok(results)
}
