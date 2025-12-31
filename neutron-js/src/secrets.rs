use anyhow::Result;
use lazy_static::lazy_static;
use neutron_types::SecretResult;
use regex::Regex;
use std::collections::HashSet;

use crate::discovery::JsFile;

lazy_static! {
    // Regex patterns for finding secrets
    static ref SECRET_PATTERNS: Vec<(Regex, &'static str)> = vec![
        // AWS Access Key
        (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "AWS Access Key"),
        
        // AWS Secret Key
        (Regex::new(r#"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"#).unwrap(), "AWS Secret Key"),
        
        // GitHub Token
        (Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(), "GitHub Token"),
        
        // GitHub OAuth
        (Regex::new(r"gho_[a-zA-Z0-9]{36}").unwrap(), "GitHub OAuth Token"),
        
        // Google API Key
        (Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(), "Google API Key"),
        
        // Firebase
        (Regex::new(r#"(?i)firebase[_-]?(?:api[_-]?key|token).{0,30}?['\"][0-9a-zA-Z_-]{20,}['\"]"#).unwrap(), "Firebase Key"),
        
        // Slack Token
        (Regex::new(r"xox[baprs]-[0-9a-zA-Z]{10,48}").unwrap(), "Slack Token"),
        
        // Stripe Key
        (Regex::new(r"sk_live_[0-9a-zA-Z]{24}").unwrap(), "Stripe Secret Key"),
        
        // Private Key
        (Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(), "Private Key"),
        
        // Generic API Key patterns
        (Regex::new(r#"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z_-]{20,})['\"]"#).unwrap(), "API Key"),
        
        // Generic Secret patterns
        (Regex::new(r#"(?i)secret['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z_-]{20,})['\"]"#).unwrap(), "Secret"),
        
        // Generic Token patterns
        (Regex::new(r#"(?i)token['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z_-]{20,})['\"]"#).unwrap(), "Token"),
        
        // JWT
        (Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap(), "JWT Token"),
    ];
}

/// Hunt for secrets in JavaScript files
pub async fn hunt_secrets(js_files: &[JsFile]) -> Result<Vec<SecretResult>> {
    tracing::info!("Hunting for secrets in {} JavaScript files", js_files.len());
    
    let mut all_secrets = HashSet::new();
    let mut results = Vec::new();
    
    for js_file in js_files {
        let secrets = find_secrets_in_js(&js_file.content, &js_file.url);
        
        for secret in secrets {
            // Use hash to avoid duplicate secrets
            let hash = format!("{}-{}", secret.secret_type, secret.value);
            if all_secrets.insert(hash) {
                results.push(secret);
            }
        }
    }
    
    tracing::info!("Found {} potential secrets", results.len());
    Ok(results)
}

/// Find secrets in JavaScript content
fn find_secrets_in_js(js_content: &str, source_url: &str) -> Vec<SecretResult> {
    let mut secrets = Vec::new();
    
    for (pattern, secret_type) in SECRET_PATTERNS.iter() {
        for cap in pattern.captures_iter(js_content) {
            let value = if let Some(group) = cap.get(1) {
                group.as_str().to_string()
            } else {
                cap.get(0).unwrap().as_str().to_string()
            };
            
            // Calculate confidence based on secret type and context
            let confidence = calculate_confidence(secret_type, &value);
            
            // Only report if confidence is above threshold
            if confidence > 0.3 {
                secrets.push(SecretResult {
                    secret_type: secret_type.to_string(),
                    value,
                    source_url: source_url.to_string(),
                    confidence,
                });
            }
        }
    }
    
    secrets
}

/// Calculate confidence score for a secret
fn calculate_confidence(secret_type: &str, value: &str) -> f32 {
    let mut confidence = 0.5; // Base confidence
    
    // High confidence for well-defined formats
    if secret_type.contains("AWS") || secret_type.contains("GitHub") {
        confidence = 0.9;
    }
    
    // Lower confidence for generic patterns
    if secret_type == "API Key" || secret_type == "Secret" || secret_type == "Token" {
        confidence = 0.4;
        
        // But increase if value looks substantial
        if value.len() > 30 && has_good_entropy(value) {
            confidence = 0.6;
        }
    }
    
    // Reduce confidence for obviously fake values
    if value.to_lowercase().contains("example") 
        || value.to_lowercase().contains("test")
        || value.to_lowercase().contains("demo")
        || value == "xxxxxxxx" {
        confidence = 0.1;
    }
    
    confidence
}

/// Check if a string has good entropy (randomness)
fn has_good_entropy(s: &str) -> bool {
    let mut char_counts = std::collections::HashMap::new();
    
    for c in s.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }
    
    // If most characters only appear once, entropy is good
    let unique_chars = char_counts.len();
    let total_chars = s.len();
    
    (unique_chars as f32 / total_chars as f32) > 0.5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_secrets() {
        let js = r#"
            const awsKey = "AKIAIOSFODNN7EXAMPLE";
            const apiKey = "sk_live_1234567890abcdefghij";
            const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        "#;
        
        let secrets = find_secrets_in_js(js, "test.js");
        assert!(secrets.len() >= 2);
    }

    #[test]
    fn test_has_good_entropy() {
        assert!(has_good_entropy("aB3xY9mK2pQ7"));
        assert!(!has_good_entropy("aaaaaaaaaa"));
    }
}
