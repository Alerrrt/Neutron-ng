pub mod passive;
pub mod active;
pub mod processor;

use anyhow::Result;
use neutron_types::SubdomainResult;

/// Main entry point for subdomain enumeration
pub async fn enumerate_subdomains(
    domain: &str,
    use_passive: bool,
    use_active: bool,
) -> Result<Vec<SubdomainResult>> {
    tracing::info!("Starting subdomain enumeration for: {}", domain);
    
    let mut results = Vec::new();
    
    // Passive discovery
    if use_passive {
        let passive_results = passive::discover_passive(domain).await?;
        results.extend(passive_results);
    }
    
    // Active discovery (DNS brute-forcing)
    if use_active {
        let active_results = active::discover_active(domain).await?;
        results.extend(active_results);
    }
    
    // Process and filter results
    let processed = processor::process_subdomains(results).await?;
    
    tracing::info!("Found {} unique subdomains for {}", processed.len(), domain);
    Ok(processed)
}
