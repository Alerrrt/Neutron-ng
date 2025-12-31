use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // GraphQL patterns
    pub static ref GRAPHQL_ENDPOINT: Regex = Regex::new(
        r#"(?i)(graphql|gql|query|mutation)[^"']*|/[a-zA-Z0-9/_-]*graphql[a-zA-Z0-9/_-]*"#
    ).unwrap();
    
    // JWT token pattern
    pub static ref JWT_TOKEN: Regex = Regex::new(
        r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
    ).unwrap();
    
    // Source map pattern
    pub static ref SOURCE_MAP: Regex = Regex::new(
        r"//# sourceMappingURL=([^\s]+)"
    ).unwrap();
    
    // Discord webhook
    pub static ref DISCORD_WEBHOOK: Regex = Regex::new(
        r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"
    ).unwrap();
    
    // Slack webhook
    pub static ref SLACK_WEBHOOK: Regex = Regex::new(
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"
    ).unwrap();
    
    // Firebase URLs
    pub static ref FIREBASE_URL: Regex = Regex::new(
        r"https://[a-zA-Z0-9-]+\.firebaseio\.com|https://[a-zA-Z0-9-]+\.firebase\.com"
    ).unwrap();
    
    // Internal IPs
    pub static ref INTERNAL_IP: Regex = Regex::new(
        r"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})"
    ).unwrap();
    
    // Hidden admin routes
    pub static ref ADMIN_ROUTE: Regex = Regex::new(
        r#"["'](/[a-zA-Z0-9_/-]*(admin|dashboard|manage|config|settings|internal|private|debug|api/v[0-9])[a-zA-Z0-9_/-]*)["']"#
    ).unwrap();
    
    // GitHub tokens
    pub static ref GITHUB_TOKEN: Regex = Regex::new(
        r"(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})"
    ).unwrap();
    
    // AWS keys
    pub static ref AWS_KEY: Regex = Regex::new(
        r"(AKIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}|ACCA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})"
    ).unwrap();
    
    // Google API keys
    pub static ref GOOGLE_API_KEY: Regex = Regex::new(
        r"AIza[0-9A-Za-z\-_]{35}"
    ).unwrap();
    
    // S3 buckets
    pub static ref S3_BUCKET: Regex = Regex::new(
        r"[a-zA-Z0-9.-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9.-]+|s3-[a-zA-Z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.-]+"
    ).unwrap();
    
    // Private keys
    pub static ref PRIVATE_KEY: Regex = Regex::new(
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"
    ).unwrap();
    
    // Email addresses
    pub static ref EMAIL: Regex = Regex::new(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ).unwrap();
}

/// Extract GraphQL endpoints from JavaScript
pub fn extract_graphql_endpoints(content: &str) -> Vec<String> {
    GRAPHQL_ENDPOINT
        .find_iter(content)
        .map(|m| m.as_str().to_string())
        .filter(|s| s.contains('/'))
        .collect()
}

/// Extract JWT tokens from JavaScript
pub fn extract_jwt_tokens(content: &str) -> Vec<String> {
    JWT_TOKEN
        .find_iter(content)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Find source map references
pub fn find_source_maps(content: &str, base_url: &str) -> Vec<String> {
    SOURCE_MAP
        .captures_iter(content)
        .filter_map(|cap| cap.get(1))
        .map(|m| {
            let map_url = m.as_str();
            if map_url.starts_with("http") {
                map_url.to_string()
            } else {
                // Construct full URL
                format!("{}/{}", base_url.trim_end_matches('/'), map_url.trim_start_matches('/'))
            }
        })
        .collect()
}

/// Extract Discord webhooks
pub fn extract_discord_webhooks(content: &str) -> Vec<String> {
    DISCORD_WEBHOOK
        .find_iter(content)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Extract Slack webhooks
pub fn extract_slack_webhooks(content: &str) -> Vec<String> {
    SLACK_WEBHOOK
        .find_iter(content)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Extract Firebase URLs
pub fn extract_firebase_urls(content: &str) -> Vec<String> {
    FIREBASE_URL
        .find_iter(content)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Extract internal IP addresses
pub fn extract_internal_ips(content: &str) -> Vec<String> {
    INTERNAL_IP
        .find_iter(content)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Extract hidden admin routes
pub fn extract_admin_routes(content: &str) -> Vec<String> {
    ADMIN_ROUTE
        .captures_iter(content)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Extract GitHub tokens
pub fn extract_github_tokens(content: &str) -> Vec<String> {
    GITHUB_TOKEN
        .find_iter(content)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Extract S3 buckets
pub fn extract_s3_buckets(content: &str) -> Vec<String> {
    S3_BUCKET
        .find_iter(content)
        .map(|m| m.as_str().to_string())
        .collect()
}
