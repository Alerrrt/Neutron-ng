pub mod historical;
pub mod crawler;
pub mod processor;

use anyhow::Result;
use neutron_types::UrlResult;

/// Main entry point for URL discovery
pub async fn discover_urls(
    domain: &str,
    use_historical: bool,
    use_crawler: bool,
) -> Result<Vec<UrlResult>> {
    tracing::info!("Starting URL discovery for: {}", domain);
    
    let mut results = Vec::new();
    
    // Historical URL sources
    if use_historical {
        let historical_results = historical::discover_historical(domain).await?;
        results.extend(historical_results);
    }
    
    // Web crawler
    if use_crawler {
        let crawled_results = crawler::crawl_domain(domain).await?;
        results.extend(crawled_results);
    }
    
    // Process and filter URLs
    let processed = processor::process_urls(results).await?;
    
    tracing::info!("Found {} unique URLs for {}", processed.len(), domain);
    Ok(processed)
}
