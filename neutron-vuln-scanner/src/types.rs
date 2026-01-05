use serde::{Deserialize, Serialize};

/// Types of vulnerabilities that can be detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VulnType {
    Xss,
    SqlInjection,
    Lfi,
    OpenRedirect,
}

impl VulnType {
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnType::Xss => "XSS",
            VulnType::SqlInjection => "SQLi",
            VulnType::Lfi => "LFI",
            VulnType::OpenRedirect => "Open Redirect",
        }
    }
}

/// A detected vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub url: String,
    pub vuln_type: VulnType,
    pub parameter: String,
    pub payload: String,
    pub evidence: String,
}

/// Configuration for the vulnerability scanner
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub max_depth: usize,
    pub max_concurrent: usize,
    pub timeout_secs: u64,
    pub follow_redirects: bool,
    pub test_xss: bool,
    pub test_sqli: bool,
    pub user_agent: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_concurrent: 10,
            timeout_secs: 10,
            follow_redirects: true,
            test_xss: true,
            test_sqli: true,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36".to_string(),
        }
    }
}

/// Results from a vulnerability scan
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScanResults {
    pub total_urls_crawled: usize,
    pub vulnerabilities: Vec<Vulnerability>,
}
