pub mod discovery;
pub mod linkfinder;
pub mod secrets;

use anyhow::Result;
use neutron_types::{JsEndpointResult, SecretResult};

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
