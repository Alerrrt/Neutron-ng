use anyhow::Result;
use lazy_static::lazy_static;
use neutron_types::JsEndpointResult;
use regex::Regex;
use std::collections::HashSet;

use crate::discovery::JsFile;

lazy_static! {
    // Regex patterns for finding endpoints in JavaScript
    static ref ENDPOINT_PATTERNS: Vec<Regex> = vec![
        // API endpoints like "/api/users" or "/v1/data"
        Regex::new(r#"(?:"|')([/][a-zA-Z0-9_/\-\{\}]{3,})(?:"|')"#).unwrap(),
        
        // Full URLs
        Regex::new(r#"(?:"|')((?:https?:)?//[^"'\s]+)(?:"|')"#).unwrap(),
        
        // Common API patterns
        Regex::new(r#"(?:api|endpoint|url|path|route)[:\s]*(?:"|')([^"']+)(?:"|')"#).unwrap(),
        
        // GraphQL queries
        Regex::new(r#"(?:query|mutation)\s+\w+\s*\{[^}]+\}"#).unwrap(),
        
        // Fetch/axios patterns
        Regex::new(r#"(?:fetch|axios)\s*\(\s*(?:"|')([^"']+)(?:"|')"#).unwrap(),
    ];
}

/// Extract endpoints from JavaScript files (LinkFinder style)
pub async fn extract_endpoints(js_files: &[JsFile]) -> Result<Vec<JsEndpointResult>> {
    tracing::info!("Extracting endpoints from {} JavaScript files", js_files.len());
    
    let mut all_endpoints = HashSet::new();
    let mut results = Vec::new();
    
    for js_file in js_files {
        let endpoints = find_endpoints_in_js(&js_file.content);
        
        for endpoint in endpoints {
            if all_endpoints.insert(endpoint.clone()) {
                results.push(JsEndpointResult {
                    endpoint,
                    source_url: js_file.url.clone(),
                    method: None, // Could be enhanced to detect HTTP method
                });
            }
        }
    }
    
    tracing::info!("Extracted {} unique endpoints", results.len());
    Ok(results)
}

/// Find endpoints in JavaScript content
fn find_endpoints_in_js(js_content: &str) -> Vec<String> {
    let mut endpoints = HashSet::new();
    
    for pattern in ENDPOINT_PATTERNS.iter() {
        for cap in pattern.captures_iter(js_content) {
            if let Some(matched) = cap.get(1) {
                let endpoint = matched.as_str();
                
                // Filter out obvious non-endpoints
                if is_valid_endpoint(endpoint) {
                    endpoints.insert(endpoint.to_string());
                }
            }
        }
    }
    
    endpoints.into_iter().collect()
}

/// Validate if a string looks like an endpoint
fn is_valid_endpoint(s: &str) -> bool {
    // Must not be too short
    if s.len() < 3 {
        return false;
    }
    
    // Filter out common false positives
    let false_positives = [
        ".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ttf",
        "javascript:", "mailto:", "tel:", "data:",
    ];
    
    for fp in &false_positives {
        if s.contains(fp) {
            return false;
        }
    }
    
    // Must start with / or http
    s.starts_with('/') || s.starts_with("http")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_endpoints() {
        let js = r#"
            fetch("/api/users")
            axios.get("https://api.example.com/data")
            const endpoint = "/v1/posts"
            url: "/admin/dashboard"
        "#;
        
        let endpoints = find_endpoints_in_js(js);
        assert!(endpoints.contains(&"/api/users".to_string()));
        assert!(endpoints.len() >= 3);
    }

    #[test]
    fn test_is_valid_endpoint() {
        assert!(is_valid_endpoint("/api/users"));
        assert!(is_valid_endpoint("https://example.com/api"));
        assert!(!is_valid_endpoint("app.js"));
        assert!(!is_valid_endpoint("ab")); // too short
    }
}
