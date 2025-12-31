use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Scan session metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanSession {
    pub scan_id: String,
    pub target: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub modules_run: Vec<String>,
    pub output_directory: PathBuf,
}

/// Result storage manager
pub struct ResultStorage {
    base_dir: PathBuf,
    scan_session: ScanSession,
}

impl ResultStorage {
    /// Create a new result storage for a scan
    pub fn new(target: &str, output_dir: Option<&str>) -> Result<Self> {
        let base_dir = if let Some(dir) = output_dir {
            PathBuf::from(dir)
        } else {
            // Save in current directory instead of ./results
            PathBuf::from(".")
        };
        
        // Simple folder name: just the sanitized target (no timestamp)
        let scan_id = sanitize_target(target);
        
        let timestamp = Utc::now();
        
        // Create scan directory
        let scan_dir = base_dir.join(&scan_id);
        fs::create_dir_all(&scan_dir)?;
        
        let scan_session = ScanSession {
            scan_id: scan_id.clone(),
            target: target.to_string(),
            start_time: timestamp,
            end_time: None,
            modules_run: Vec::new(),
            output_directory: scan_dir.clone(),
        };
        
        Ok(Self {
            base_dir,
            scan_session,
        })
    }
    
    /// Get the scan directory path
    pub fn scan_dir(&self) -> &PathBuf {
        &self.scan_session.output_directory
    }
    
    /// Get the scan ID
    pub fn scan_id(&self) -> &str {
        &self.scan_session.scan_id
    }
    
    /// Save metadata about a module run
    pub fn record_module(&mut self, module_name: &str) {
        if !self.scan_session.modules_run.contains(&module_name.to_string()) {
            self.scan_session.modules_run.push(module_name.to_string());
        }
    }
    
    /// Finalize the scan and save metadata
    pub fn finalize(&mut self) -> Result<()> {
        self.scan_session.end_time = Some(Utc::now());
        
        let metadata_path = self.scan_session.output_directory.join("scan_metadata.json");
        let json = serde_json::to_string_pretty(&self.scan_session)?;
        fs::write(metadata_path, json)?;
        
        Ok(())
    }
    
    /// Save subdomains to file
    pub fn save_subdomains(&self, results: &[neutron_types::SubdomainResult]) -> Result<PathBuf> {
        // Save as a simple list
        let list_path = self.scan_session.output_directory.join("subdomains.txt");
        let list: Vec<String> = results.iter()
            .map(|r| format!("{} → {} ({})", 
                r.subdomain, 
                r.resolved_ips.join(", "),
                r.source
            ))
            .collect();
        fs::write(&list_path, list.join("\n"))?;
        
        Ok(list_path)
    }
    
    /// Save URLs to file
    pub fn save_urls(&self, results: &[neutron_types::UrlResult]) -> Result<PathBuf> {
        // Save as a simple list
        let list_path = self.scan_session.output_directory.join("urls.txt");
        let list: Vec<String> = results.iter()
            .map(|r| format!("{} ({})", r.url, r.source))
            .collect();
        fs::write(&list_path, list.join("\n"))?;
        
        Ok(list_path)
    }
    
    /// Save JavaScript endpoints to file
    pub fn save_js_endpoints(&self, results: &[neutron_types::JsEndpointResult]) -> Result<PathBuf> {
        // Save as a simple list
        let list_path = self.scan_session.output_directory.join("js_endpoints.txt");
        let list: Vec<String> = results.iter()
            .map(|r| format!("{} (from: {})", r.endpoint, r.source_url))
            .collect();
        fs::write(&list_path, list.join("\n"))?;
        
        Ok(list_path)
    }
    
    /// Save secrets to file
    pub fn save_secrets(&self, results: &[neutron_types::SecretResult]) -> Result<PathBuf> {
        // Save summary
        let summary_path = self.scan_session.output_directory.join("secrets.txt");
        let mut summary = String::new();
        summary.push_str(&format!("# Secrets Found: {}\n\n", results.len()));
        
        for secret in results {
            summary.push_str(&format!(
                "[{:.0}%] {} - {} characters\n  Source: {}\n  Value: {}...\n\n",
                secret.confidence * 100.0,
                secret.secret_type,
                secret.value.len(),
                secret.source_url,
                &secret.value.chars().take(20).collect::<String>()
            ));
        }
        
        fs::write(&summary_path, summary)?;
        
        Ok(summary_path)
    }
    
    /// Save DNS records to file
    pub fn save_dns_records(&self, results: &[neutron_types::DnsRecord]) -> Result<PathBuf> {
        let path = self.scan_session.output_directory.join("dns_records.txt");
        let list: Vec<String> = results.iter()
            .map(|r| format!("{:6} {}", r.record_type, r.value))
            .collect();
        fs::write(&path, list.join("\n"))?;
        Ok(path)
    }
    
    /// Save technologies to file
    pub fn save_technologies(&self, results: &[neutron_types::Technology]) -> Result<PathBuf> {
        let path = self.scan_session.output_directory.join("technologies.txt");
        let list: Vec<String> = results.iter()
            .map(|t| {
                let version = t.version.as_deref().unwrap_or("unknown");
                format!("[{}] {} {} ({}% confidence)", 
                    t.category, t.name, version, t.confidence)
            })
            .collect();
        fs::write(&path, list.join("\n"))?;
        Ok(path)
    }
    
    /// Save network intelligence to file
    pub fn save_network_intel(&self, intel: &neutron_types::NetworkIntelligence) -> Result<PathBuf> {
        let path = self.scan_session.output_directory.join("network_intel.txt");
        let mut content = String::new();
        
        content.push_str(&format!("# Network Intelligence for {}\n\n", intel.domain));
        
        if !intel.asn_numbers.is_empty() {
            content.push_str("## ASN Numbers\n");
            for asn in &intel.asn_numbers {
                content.push_str(&format!("{}\n", asn));
            }
            content.push('\n');
        }
        
        if !intel.ip_ranges.is_empty() {
            content.push_str("## IP Ranges\n");
            for range in &intel.ip_ranges {
                content.push_str(&format!("{}\n", range));
            }
            content.push('\n');
        }
        
        if !intel.reverse_dns.is_empty() {
            content.push_str("## Reverse DNS\n");
            for ptr in &intel.reverse_dns {
                content.push_str(&format!("{}\n", ptr));
            }
            content.push('\n');
        }
        
        if !intel.related_domains.is_empty() {
            content.push_str("## Related Domains\n");
            for domain in &intel.related_domains {
                content.push_str(&format!("{}\n", domain));
            }
        }
        
        fs::write(&path, content)?;
        Ok(path)
    }
    
    /// Create a summary report
    pub fn create_summary(&self, 
        subdomains: usize, 
        urls: usize, 
        endpoints: usize, 
        secrets: usize
    ) -> Result<()> {
        let summary_path = self.scan_session.output_directory.join("SUMMARY.txt");
        
        let duration = if let Some(end) = self.scan_session.end_time {
            let duration = end.signed_duration_since(self.scan_session.start_time);
            format!("{} seconds", duration.num_seconds())
        } else {
            "In progress".to_string()
        };
        
        let summary = format!(
r#"# Neutron-ng Scan Summary

Target: {}
Scan ID: {}
Start Time: {}
Duration: {}

## Results
- Subdomains: {}
- URLs: {}
- JS Endpoints: {}  
- Secrets: {}

## Files Generated
- subdomains.txt
- urls.txt
- js_endpoints.txt
- secrets.txt
- scan_metadata.json

## Modules Run
{}

---
Generated by Neutron-ng v{}
"#,
            self.scan_session.target,
            self.scan_session.scan_id,
            self.scan_session.start_time.format("%Y-%m-%d %H:%M:%S UTC"),
            duration,
            subdomains,
            urls,
            endpoints,
            secrets,
            self.scan_session.modules_run.iter()
                .map(|m| format!("- {}", m))
                .collect::<Vec<_>>()
                .join("\n"),
            env!("CARGO_PKG_VERSION")
        );
        
        fs::write(summary_path, summary)?;
        
        Ok(())
    }
}

/// Sanitize target name for use in filename
fn sanitize_target(target: &str) -> String {
    target
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_target() {
        assert_eq!(sanitize_target("example.com"), "example.com");
        assert_eq!(sanitize_target("https://example.com"), "example.com");
        assert_eq!(sanitize_target("sub.example.com:443/path"), "sub.example.com_443_path");
    }
}
