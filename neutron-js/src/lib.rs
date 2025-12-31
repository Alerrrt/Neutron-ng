pub mod discovery;
pub mod linkfinder;
pub mod secrets;
pub mod advanced_patterns;

use anyhow::Result;
use neutron_types::{JsEndpointResult, SecretResult};

pub struct AdvancedJsResults {
    pub endpoints: Vec<JsEndpointResult>,
    pub secrets: Vec<SecretResult>,
    pub graphql_endpoints: Vec<String>,
    pub jwt_tokens: Vec<String>,
    pub source_maps: Vec<String>,
    pub discord_webhooks: Vec<String>,
    pub slack_webhooks: Vec<String>,
    pub firebase_urls: Vec<String>,
    pub internal_ips: Vec<String>,
    pub admin_routes: Vec<String>,
    pub github_tokens: Vec<String>,
    pub s3_buckets: Vec<String>,
}

/// Main entry point for JavaScript analysis
pub async fn analyze_javascript(
    urls: &[String],
) -> Result<(Vec<JsEndpointResult>, Vec<SecretResult>)> {
    tracing::info!("Starting JavaScript analysis for {} URLs", urls.len());
    
    // Discover JavaScript files from provided URLs
    let js_files = discovery::discover_js_files(urls).await?;
    tracing::info!("Found {} JavaScript files", js_files.len());
    
    // Extract endpoints from JavaScript files
    let endpoints = linkfinder::extract_endpoints(&js_files).await?;
    tracing::info!("Extracted {} endpoints from JavaScript", endpoints.len());
    
    // Hunt for secrets in JavaScript files
    let secrets = secrets::hunt_secrets(&js_files).await?;
    tracing::info!("Found {} potential secrets in JavaScript", secrets.len());
    
    Ok((endpoints, secrets))
}

/// Advanced JavaScript analysis with all pattern extraction
pub async fn analyze_javascript_advanced(
    urls: &[String],
) -> Result<AdvancedJsResults> {
    tracing::info!("Starting advanced JavaScript analysis for {} URLs", urls.len());
    
    // Discover JavaScript files
    let js_files = discovery::discover_js_files(urls).await?;
    tracing::info!("Found {} JavaScript files", js_files.len());
    
    let mut results = AdvancedJsResults {
        endpoints: Vec::new(),
        secrets: Vec::new(),
        graphql_endpoints: Vec::new(),
        jwt_tokens: Vec::new(),
        source_maps: Vec::new(),
        discord_webhooks: Vec::new(),
        slack_webhooks: Vec::new(),
        firebase_urls: Vec::new(),
        internal_ips: Vec::new(),
        admin_routes: Vec::new(),
        github_tokens: Vec::new(),
        s3_buckets: Vec::new(),
    };
    
    // Standard extraction
    results.endpoints = linkfinder::extract_endpoints(&js_files).await?;
    results.secrets = secrets::hunt_secrets(&js_files).await?;
    
    // Advanced pattern extraction from all JS files
    for (url, content) in &js_files {
        // GraphQL endpoints
        let graphql = advanced_patterns::extract_graphql_endpoints(content);
        results.graphql_endpoints.extend(graphql);
        
        // JWT tokens
        let jwts = advanced_patterns::extract_jwt_tokens(content);
        results.jwt_tokens.extend(jwts);
        
        // Source maps
        let maps = advanced_patterns::find_source_maps(content, url);
        results.source_maps.extend(maps);
        
        // Discord webhooks
        let discord = advanced_patterns::extract_discord_webhooks(content);
        results.discord_webhooks.extend(discord);
        
        // Slack webhooks
        let slack = advanced_patterns::extract_slack_webhooks(content);
        results.slack_webhooks.extend(slack);
        
        // Firebase URLs
        let firebase = advanced_patterns::extract_firebase_urls(content);
        results.firebase_urls.extend(firebase);
        
        // Internal IPs
        let ips = advanced_patterns::extract_internal_ips(content);
        results.internal_ips.extend(ips);
        
        // Admin routes
        let routes = advanced_patterns::extract_admin_routes(content);
        results.admin_routes.extend(routes);
        
        // GitHub tokens
        let gh_tokens = advanced_patterns::extract_github_tokens(content);
        results.github_tokens.extend(gh_tokens);
        
        // S3 buckets
        let s3 = advanced_patterns::extract_s3_buckets(content);
        results.s3_buckets.extend(s3);
    }
    
    // Deduplicate all results
    results.graphql_endpoints.sort();
    results.graphql_endpoints.dedup();
    results.jwt_tokens.sort();
    results.jwt_tokens.dedup();
    results.source_maps.sort();
    results.source_maps.dedup();
    results.discord_webhooks.sort();
    results.discord_webhooks.dedup();
    results.slack_webhooks.sort();
    results.slack_webhooks.dedup();
    results.firebase_urls.sort();
    results.firebase_urls.dedup();
    results.internal_ips.sort();
    results.internal_ips.dedup();
    results.admin_routes.sort();
    results.admin_routes.dedup();
    results.github_tokens.sort();
    results.github_tokens.dedup();
    results.s3_buckets.sort();
    results.s3_buckets.dedup();
    
    tracing::info!("Advanced analysis complete:");
    tracing::info!("  - Endpoints: {}", results.endpoints.len());
    tracing::info!("  - Secrets: {}", results.secrets.len());
    tracing::info!("  - GraphQL endpoints: {}", results.graphql_endpoints.len());
    tracing::info!("  - JWT tokens: {}", results.jwt_tokens.len());
    tracing::info!("  - Source maps: {}", results.source_maps.len());
    tracing::info!("  - Discord webhooks: {}", results.discord_webhooks.len());
    tracing::info!("  - Slack webhooks: {}", results.slack_webhooks.len());
    tracing::info!("  - Firebase URLs: {}", results.firebase_urls.len());
    tracing::info!("  - Internal IPs: {}", results.internal_ips.len());
    tracing::info!("  - Admin routes: {}", results.admin_routes.len());
    tracing::info!("  - GitHub tokens: {}", results.github_tokens.len());
    tracing::info!("  - S3 buckets: {}", results.s3_buckets.len());
    
    Ok(results)
}
