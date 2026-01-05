pub mod certsh;
pub mod crtsh;
pub mod virustotal;
pub mod securitytrails;
pub mod chaos;
pub mod bufferover;
pub mod rapiddns;
pub mod anubis;
pub mod recondev;
pub mod subdomaincenter;
pub mod phonebook;
pub mod thc;

use anyhow::Result;
use neutron_core::HttpClient;
use neutron_types::SubdomainResult;
use std::collections::HashSet;

/// Discover subdomains using all passive sources
pub async fn discover_passive(domain: &str) -> Result<Vec<SubdomainResult>> {
    tracing::info!("Starting passive subdomain discovery for: {}", domain);
    
    let http_client = HttpClient::new(
        std::time::Duration::from_secs(30),
        None,
        format!("Neutron-ng/{}", env!("CARGO_PKG_VERSION")),
        100,
    )?;
    
    let mut all_subdomains = HashSet::new();
    let mut results = Vec::new();
    
    // Run all passive sources concurrently
    let domain_clone = domain.to_string();
    let sources = vec![
        tokio::spawn(certsh::fetch_certsh(domain_clone.clone(), http_client.clone())),
        tokio::spawn(crtsh::fetch_crtsh(domain_clone.clone(), http_client.clone())),
        tokio::spawn(virustotal::fetch_virustotal(domain_clone.clone(), http_client.clone())),
        tokio::spawn(securitytrails::fetch_securitytrails(domain_clone.clone(), http_client.clone())),
        tokio::spawn(chaos::fetch_chaos(domain_clone.clone(), http_client.clone())),
        tokio::spawn(bufferover::fetch_bufferover(domain_clone.clone(), http_client.clone())),
        tokio::spawn(rapiddns::fetch_rapiddns(domain_clone.clone(), http_client.clone())),
        tokio::spawn(anubis::fetch_anubis(domain_clone.clone(), http_client.clone())),
        tokio::spawn(recondev::fetch_recondev(domain_clone.clone(), http_client.clone())),
        tokio::spawn(subdomaincenter::fetch_subdomaincenter(domain_clone.clone(), http_client.clone())),
        tokio::spawn(phonebook::fetch_phonebook(domain_clone.clone(), http_client.clone())),
        tokio::spawn(thc::fetch_thc(domain_clone.clone(), http_client.clone())),
    ];
    
    let source_names = vec![
        "cert.sh", "crt.sh", "VirusTotal", "SecurityTrails", 
        "Chaos", "BufferOver", "RapidDNS", "Anubis", "recon.dev",
        "subdomain.center", "phonebook.cz", "ip.thc.org"
    ];
    
    // Collect results from all sources
    for (idx, source) in sources.into_iter().enumerate() {
        let source_name = source_names.get(idx).unwrap_or(&"unknown");
        match source.await {
            Ok(Ok(subdomains)) => {
                tracing::info!("{} found {} subdomains", source_name, subdomains.len());
                for subdomain in subdomains {
                    if all_subdomains.insert(subdomain.clone()) {
                        results.push(SubdomainResult {
                            subdomain,
                            source: source_name.to_string(),
                            resolved_ips: vec![],
                            is_wildcard: false,
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
    
    tracing::info!("Passive discovery found {} unique subdomains", results.len());
    Ok(results)
}
