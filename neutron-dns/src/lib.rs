use anyhow::Result;
use neutron_types::DnsRecord;
use tracing::{info, warn};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;

pub async fn enumerate_dns_records(domain: &str) -> Result<Vec<DnsRecord>> {
    info!("Starting DNS enumeration for: {}", domain);
    
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default()
    );
    
    let mut records = Vec::new();
    
    // A Records
    match resolver.ipv4_lookup(domain).await {
        Ok(lookup) => {
            for ip in lookup.iter() {
                records.push(DnsRecord {
                    record_type: "A".to_string(),
                    value: ip.to_string(),
                    domain: domain.to_string(),
                });
            }
            info!("Found {} A records", lookup.iter().count());
        }
        Err(e) => warn!("A record lookup failed: {}", e),
    }
    
    // AAAA Records (IPv6)
    match resolver.ipv6_lookup(domain).await {
        Ok(lookup) => {
            for ip in lookup.iter() {
                records.push(DnsRecord {
                    record_type: "AAAA".to_string(),
                    value: ip.to_string(),
                    domain: domain.to_string(),
                });
            }
            info!("Found {} AAAA records", lookup.iter().count());
        }
        Err(e) => warn!("AAAA record lookup failed: {}", e),
    }
    
    // MX Records (Mail servers)
    match resolver.mx_lookup(domain).await {
        Ok(lookup) => {
            for mx in lookup.iter() {
                records.push(DnsRecord {
                    record_type: "MX".to_string(),
                    value: format!("{} (priority: {})", mx.exchange(), mx.preference()),
                    domain: domain.to_string(),
                });
            }
            info!("Found {} MX records", lookup.iter().count());
        }
        Err(e) => warn!("MX record lookup failed: {}", e),
    }
    
    // TXT Records (SPF, DKIM, verification tokens)
    match resolver.txt_lookup(domain).await {
        Ok(lookup) => {
            for txt in lookup.iter() {
                let value = txt.iter()
                    .map(|data| String::from_utf8_lossy(data))
                    .collect::<Vec<_>>()
                    .join("");
                records.push(DnsRecord {
                    record_type: "TXT".to_string(),
                    value,
                    domain: domain.to_string(),
                });
            }
            info!("Found {} TXT records", lookup.iter().count());
        }
        Err(e) => warn!("TXT record lookup failed: {}", e),
    }
    
    // NS Records (Name servers)
    match resolver.ns_lookup(domain).await {
        Ok(lookup) => {
            for ns in lookup.iter() {
                records.push(DnsRecord {
                    record_type: "NS".to_string(),
                    value: ns.to_string(),
                    domain: domain.to_string(),
                });
            }
            info!("Found {} NS records", lookup.iter().count());
        }
        Err(e) => warn!("NS record lookup failed: {}", e),
    }
    
    info!("DNS enumeration complete: {} total records", records.len());
    Ok(records)
}
