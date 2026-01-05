pub mod types;
pub mod detectors;
pub mod crawler;

pub use types::{ScanConfig, ScanResults, Vulnerability, VulnType};
pub use crawler::VulnCrawler;

use anyhow::Result;
use std::fs;
use std::path::Path;

/// Read URLs from a Neutron scan directory
pub fn read_urls_from_scan(scan_dir: &Path) -> Result<Vec<String>> {
    let mut urls = Vec::new();
    
    // Try reading from 03_http/live_urls.txt
    let http_file = scan_dir.join("03_http/live_urls.txt");
    if http_file.exists() {
        let content = fs::read_to_string(&http_file)?;
        urls.extend(content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    
    // Try reading from 04_crawl/all_endpoints.txt
    let crawl_file = scan_dir.join("04_crawl/all_endpoints.txt");
    if crawl_file.exists() {
        let content = fs::read_to_string(&crawl_file)?;
        urls.extend(content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    
    // Deduplicate
    urls.sort();
    urls.dedup();
    
    Ok(urls)
}

/// Save scan results to the scan directory
pub fn save_results(scan_dir: &Path, results: &ScanResults) -> Result<()> {
    let vuln_dir = scan_dir.join("05_vuln_scan");
    fs::create_dir_all(&vuln_dir)?;
    
    // Save all crawled URLs
    let all_urls_file = vuln_dir.join("all_crawled_urls.txt");
    // Note: We'd need to track this separately in the crawler
    
    // Save vulnerabilities by type
    let xss_vulns: Vec<_> = results.vulnerabilities.iter()
        .filter(|v| v.vuln_type == VulnType::Xss)
        .collect();
    
    if !xss_vulns.is_empty() {
        let xss_file = vuln_dir.join("xss_vulnerabilities.txt");
        let content = xss_vulns.iter()
            .map(|v| format!("{} (param: {}, payload: {})", v.url, v.parameter, v.payload))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&xss_file, content)?;
        println!("  💾 Saved {} XSS vulnerabilities to: {}", xss_vulns.len(), xss_file.display());
    }
    
    let sqli_vulns: Vec<_> = results.vulnerabilities.iter()
        .filter(|v| v.vuln_type == VulnType::SqlInjection)
        .collect();
    
    if !sqli_vulns.is_empty() {
        let sqli_file = vuln_dir.join("sqli_vulnerabilities.txt");
        let content = sqli_vulns.iter()
            .map(|v| format!("{} (param: {}, payload: {})", v.url, v.parameter, v.payload))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&sqli_file, content)?;
        println!("  💾 Saved {} SQLi vulnerabilities to: {}", sqli_vulns.len(), sqli_file.display());
    }
    
    // Save JSON summary
    let summary_file = vuln_dir.join("summary.json");
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&summary_file, json)?;
    println!("  💾 Saved scan summary to: {}", summary_file.display());
    
    Ok(())
}
