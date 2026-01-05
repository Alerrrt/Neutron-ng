use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use std::collections::HashMap;
use url::Url;
use crate::types::{Vulnerability, VulnType};

/// XSS payloads for testing
const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
];

/// SQLi payloads for testing
const SQLI_PAYLOADS: &[&str] = &[
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
];

/// SQL error patterns
const SQL_ERROR_PATTERNS: &[&str] = &[
    r"(?i)you have an error in your sql syntax",
    r"(?i)warning: mysql",
    r"(?i)unclosed quotation mark",
    r"(?i)syntax error.*sql",
    r"(?i)mysql_fetch",
    r"(?i)pg_query",
];

pub struct XssDetector {
    payloads: Vec<String>,
}

impl XssDetector {
    pub fn new() -> Self {
        Self {
            payloads: XSS_PAYLOADS.iter().map(|s| s.to_string()).collect(),
        }
    }
    
    /// Test URL for XSS vulnerabilities
    pub async fn test(&self, client: &Client, url: &str) -> Result<Vec<Vulnerability>> {
        let parsed = Url::parse(url)?;
        let query_pairs: HashMap<String, String> = parsed.query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        
        if query_pairs.is_empty() {
            return Ok(Vec::new());
        }
        
        let mut vulns = Vec::new();
        
        for (param, _original_value) in &query_pairs {
            for payload in &self.payloads {
                let mut new_params = query_pairs.clone();
                new_params.insert(param.clone(), payload.clone());
                
                let mut test_url = parsed.clone();
                test_url.set_query(Some(&encode_params(&new_params)));
                
                if let Ok(response) = client.get(test_url.as_str()).send().await {
                    if let Ok(body) = response.text().await {
                        if body.contains(payload) {
                            vulns.push(Vulnerability {
                                url: url.to_string(),
                                vuln_type: VulnType::Xss,
                                parameter: param.clone(),
                                payload: payload.clone(),
                                evidence: format!("Payload reflected in response"),
                            });
                            break; // Found vuln in this param, move to next
                        }
                    }
                }
            }
        }
        
        Ok(vulns)
    }
}

pub struct SqliDetector {
    payloads: Vec<String>,
    error_patterns: Vec<Regex>,
}

impl SqliDetector {
    pub fn new() -> Result<Self> {
        let error_patterns = SQL_ERROR_PATTERNS.iter()
            .map(|pattern| Regex::new(pattern))
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(Self {
            payloads: SQLI_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            error_patterns,
        })
    }
    
    /// Test URL for SQL injection vulnerabilities
    pub async fn test(&self, client: &Client, url: &str) -> Result<Vec<Vulnerability>> {
        let parsed = Url::parse(url)?;
        let query_pairs: HashMap<String, String> = parsed.query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        
        if query_pairs.is_empty() {
            return Ok(Vec::new());
        }
        
        let mut vulns = Vec::new();
        
        for (param, _original_value) in &query_pairs {
            for payload in &self.payloads {
                let mut new_params = query_pairs.clone();
                new_params.insert(param.clone(), payload.clone());
                
                let mut test_url = parsed.clone();
                test_url.set_query(Some(&encode_params(&new_params)));
                
                if let Ok(response) = client.get(test_url.as_str()).send().await {
                    if let Ok(body) = response.text().await {
                        // Check for SQL error patterns
                        for pattern in &self.error_patterns {
                            if pattern.is_match(&body) {
                                vulns.push(Vulnerability {
                                    url: url.to_string(),
                                    vuln_type: VulnType::SqlInjection,
                                    parameter: param.clone(),
                                    payload: payload.clone(),
                                    evidence: format!("SQL error detected in response"),
                                });
                                break; // Found vuln in this param
                            }
                        }
                    }
                }
            }
        }
        
        Ok(vulns)
    }
}

fn encode_params(params: &HashMap<String, String>) -> String {
    params.iter()
        .map(|(k, v)| format!("{}={}", 
            urlencoding::encode(k), 
            urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
