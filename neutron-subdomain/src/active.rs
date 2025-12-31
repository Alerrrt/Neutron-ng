use anyhow::Result;
use neutron_types::SubdomainResult;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Default wordlist for DNS brute-forcing (common subdomains)
const DEFAULT_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
    "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
    "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
    "wiki", "web", "media", "email", "images", "img", "www1", "intranet", "portal",
    "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns",
    "search", "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1",
    "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover",
    "info", "apps", "download", "remote", "db", "forums", "store", "relay", "files",
    "newsletter", "app", "live", "owa", "en", "start", "sms", "office", "exchange",
    "ipv4", "git", "uploads", "stage", "alpha", "dashboard", "v2", "public"
];

/// Perform active subdomain discovery using DNS brute-forcing
pub async fn discover_active(domain: &str) -> Result<Vec<SubdomainResult>> {
    tracing::info!("Starting active subdomain discovery for: {}", domain);
    
    // Create DNS resolver
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );
    
    let resolver = Arc::new(resolver);
    let mut results = Vec::new();
    
    // Limit concurrent DNS queries to avoid overwhelming the resolver
    let semaphore = Arc::new(Semaphore::new(50));
    let mut tasks = Vec::new();
    
    for &word in DEFAULT_WORDLIST {
        let subdomain = format!("{}.{}", word, domain);
        let resolver_clone = Arc::clone(&resolver);
        let sem_clone = Arc::clone(&semaphore);
        
        let task = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();
            resolve_subdomain(subdomain, resolver_clone).await
        });
        
        tasks.push(task);
    }
    
    // Collect results
    for task in tasks {
        if let Ok(Some(result)) = task.await {
            results.push(result);
        }
    }
    
    tracing::info!("Active discovery found {} live subdomains", results.len());
    Ok(results)
}

/// Resolve a subdomain and return result if successful
async fn resolve_subdomain(
    subdomain: String,
    resolver: Arc<TokioAsyncResolver>,
) -> Option<SubdomainResult> {
    match resolver.lookup_ip(subdomain.as_str()).await {
        Ok(lookup) => {
            let ips: Vec<String> = lookup
                .iter()
                .map(|ip| ip.to_string())
                .collect();
            
            if !ips.is_empty() {
                tracing::debug!("Resolved {}: {:?}", subdomain, ips);
                Some(SubdomainResult {
                    subdomain,
                    source: "active_bruteforce".to_string(),
                    resolved_ips: ips,
                    is_wildcard: false,
                })
            } else {
                None
            }
        }
        Err(_) => None,
    }
}
