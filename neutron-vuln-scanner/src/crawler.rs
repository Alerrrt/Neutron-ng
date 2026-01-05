use anyhow::Result;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use url::Url;

use crate::detectors::{SqliDetector, XssDetector};
use crate::types::{ScanConfig, ScanResults, Vulnerability};

pub struct VulnCrawler {
    config: ScanConfig,
    client: Client,
    xss_detector: XssDetector,
    sqli_detector: SqliDetector,
    visited: Arc<Mutex<HashSet<String>>>,
    vulnerabilities: Arc<Mutex<Vec<Vulnerability>>>,
}

impl VulnCrawler {
    pub fn new(config: ScanConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent(&config.user_agent)
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(3)
            } else {
                reqwest::redirect::Policy::none()
            })
            .build()?;
        
        Ok(Self {
            config,
            client,
            xss_detector: XssDetector::new(),
            sqli_detector: SqliDetector::new()?,
            visited: Arc::new(Mutex::new(HashSet::new())),
            vulnerabilities: Arc::new(Mutex::new(Vec::new())),
        })
    }
    
    /// Crawl and scan a list of starting URLs
    pub async fn scan(&self, start_urls: Vec<String>) -> Result<ScanResults> {
        info!("Starting vulnerability scan on {} URLs", start_urls.len());
        
        // Process URLs concurrently
        stream::iter(start_urls)
            .map(|url| self.crawl_recursive(url, 0))
            .buffer_unordered(self.config.max_concurrent)
            .collect::<Vec<_>>()
            .await;
        
        let visited = self.visited.lock().await;
        let vulnerabilities = self.vulnerabilities.lock().await;
        
        info!("Scan complete: {} URLs crawled, {} vulnerabilities found", 
            visited.len(), vulnerabilities.len());
        
        Ok(ScanResults {
            total_urls_crawled: visited.len(),
            vulnerabilities: vulnerabilities.clone(),
        })
    }
    
    async fn crawl_recursive(&self, url: String, depth: usize) -> Result<()> {
        if depth > self.config.max_depth {
            return Ok(());
        }
        
        // Check if already visited
        {
            let mut visited = self.visited.lock().await;
            if visited.contains(&url) {
                return Ok(());
            }
            visited.insert(url.clone());
        }
        
        debug!("Crawling: {} (depth: {})", url, depth);
        
        // Get the base domain for scope checking
        let base_url = Url::parse(&url)?;
        let base_domain = base_url.host_str().ok_or(anyhow::anyhow!("No host"))?.to_string();
        
        // Fetch page
        let response = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to fetch {}: {}", url, e);
                return Ok(());
            }
        };
        
        if !response.status().is_success() {
            return Ok(());
        }
        
        let body = match response.text().await {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };
        
        // Test for vulnerabilities if URL has parameters
        if base_url.query().is_some() {
            self.test_vulnerabilities(&url).await?;
        }
        
        // Extract and crawl links
        let document = Html::parse_document(&body);
        let link_selector = Selector::parse("a[href]").unwrap();
        
        let mut new_urls = Vec::new();
        for element in document.select(&link_selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(absolute_url) = base_url.join(href) {
                    let url_str = absolute_url.to_string();
                    
                    // Check if in scope (same domain)
                    if let Some(host) = absolute_url.host_str() {
                        if host == base_domain {
                            // Skip certain schemes
                            if absolute_url.scheme() == "http" || absolute_url.scheme() == "https" {
                                new_urls.push(url_str);
                            }
                        }
                    }
                }
            }
        }
        
        // Recursively crawl discovered URLs
        stream::iter(new_urls)
            .map(|url| self.crawl_recursive(url, depth + 1))
            .buffer_unordered(self.config.max_concurrent)
            .collect::<Vec<_>>()
            .await;
        
        Ok(())
    }
    
    async fn test_vulnerabilities(&self, url: &str) -> Result<()> {
        let mut vulns = Vec::new();
        
        // Test XSS
        if self.config.test_xss {
            if let Ok(xss_vulns) = self.xss_detector.test(&self.client, url).await {
                for v in xss_vulns {
                    info!("[XSS] Found vulnerability: {} (param: {})", url, v.parameter);
                    vulns.push(v);
                }
            }
        }
        
        // Test SQL Injection
        if self.config.test_sqli {
            if let Ok(sqli_vulns) = self.sqli_detector.test(&self.client, url).await {
                for v in sqli_vulns {
                    info!("[SQLi] Found vulnerability: {} (param: {})", url, v.parameter);
                    vulns.push(v);
                }
            }
        }
        
        // Store vulnerabilities
        if !vulns.is_empty() {
            let mut vulnerabilities = self.vulnerabilities.lock().await;
            vulnerabilities.extend(vulns);
        }
        
        Ok(())
    }
}
