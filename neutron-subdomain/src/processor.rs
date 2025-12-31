use anyhow::Result;
use neutron_types::SubdomainResult;
use std::collections::{HashMap, HashSet};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// Process and filter subdomains (deduplication, wildcard detection, DNS verification)
pub async fn process_subdomains(results: Vec<SubdomainResult>) -> Result<Vec<SubdomainResult>> {
    tracing::info!("Processing {} subdomains", results.len());
    
    // Step 1: Deduplicate by subdomain name
    let mut unique_subdomains: HashMap<String, SubdomainResult> = HashMap::new();
    
    for result in results {
        unique_subdomains
            .entry(result.subdomain.clone())
            .or_insert(result);
    }
    
    tracing::info!("After deduplication: {} unique subdomains", unique_subdomains.len());
    
    // Step 2: Resolve all subdomains to get IPs
    let resolved = resolve_all_subdomains(unique_subdomains.into_values().collect()).await?;
    
    // Step 3: Detect wildcards
    let filtered = detect_wildcards(resolved).await?;
    
    tracing::info!("After wildcard filtering: {} subdomains", filtered.len());
    
    Ok(filtered)
}

/// Resolve DNS for all subdomains
async fn resolve_all_subdomains(subdomains: Vec<SubdomainResult>) -> Result<Vec<SubdomainResult>> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );
    
    let mut resolved = Vec::new();
    
    for mut subdomain in subdomains {
        // Skip if already resolved
        if !subdomain.resolved_ips.is_empty() {
            resolved.push(subdomain);
            continue;
        }
        
        // Resolve the subdomain
        match resolver.lookup_ip(subdomain.subdomain.as_str()).await {
            Ok(lookup) => {
                let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                subdomain.resolved_ips = ips;
                resolved.push(subdomain);
            }
            Err(_) => {
                // Subdomain doesn't resolve, skip it
                tracing::debug!("Subdomain {} doesn't resolve", subdomain.subdomain);
            }
        }
    }
    
    Ok(resolved)
}

/// Detect and filter wildcard subdomains
async fn detect_wildcards(subdomains: Vec<SubdomainResult>) -> Result<Vec<SubdomainResult>> {
    if subdomains.is_empty() {
        return Ok(subdomains);
    }
    
    // Extract base domain from first subdomain
    let first_subdomain = &subdomains[0].subdomain;
    let parts: Vec<&str> = first_subdomain.split('.').collect();
    if parts.len() < 2 {
        return Ok(subdomains);
    }
    let base_domain = parts[parts.len() - 2..].join(".");
    
    // Test random subdomains to detect wildcards
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );
    
    let random_subdomains = vec![
        format!("random-test-{}.{}", uuid::Uuid::new_v4(), base_domain),
        format!("nonexistent-{}.{}", uuid::Uuid::new_v4(), base_domain),
        format!("wildcard-check-{}.{}", uuid::Uuid::new_v4(), base_domain),
    ];
    
    let mut wildcard_ips = HashSet::new();
    
    for random_sub in random_subdomains {
        if let Ok(lookup) = resolver.lookup_ip(random_sub.as_str()).await {
            for ip in lookup.iter() {
                wildcard_ips.insert(ip.to_string());
            }
        }
    }
    
    if wildcard_ips.is_empty() {
        // No wildcard detected
        return Ok(subdomains);
    }
    
    tracing::info!("Detected wildcard IPs: {:?}", wildcard_ips);
    
    // Filter out subdomains that only resolve to wildcard IPs
    let filtered: Vec<SubdomainResult> = subdomains
        .into_iter()
        .filter(|subdomain| {
            let has_non_wildcard = subdomain
                .resolved_ips
                .iter()
                .any(|ip| !wildcard_ips.contains(ip));
            
            if !has_non_wildcard && !subdomain.resolved_ips.is_empty() {
                tracing::debug!("Filtering wildcard subdomain: {}", subdomain.subdomain);
            }
            
            has_non_wildcard
        })
        .collect();
    
    Ok(filtered)
}
