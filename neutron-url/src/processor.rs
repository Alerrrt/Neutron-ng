use anyhow::Result;
use neutron_types::UrlResult;
use std::collections::HashMap;
use url::Url;

/// Process and filter URLs (normalization, deduplication)
pub async fn process_urls(results: Vec<UrlResult>) -> Result<Vec<UrlResult>> {
    tracing::info!("Processing {} URLs", results.len());
    
    // Deduplicate by normalized URL
    let mut unique_urls: HashMap<String, UrlResult> = HashMap::new();
    
    for result in results {
        // Normalize the URL
        if let Ok(normalized) = normalize_url(&result.url) {
            unique_urls.entry(normalized).or_insert(result);
        }
    }
    
    let processed: Vec<UrlResult> = unique_urls.into_values().collect();
    
    tracing::info!("After processing: {} unique URLs", processed.len());
    Ok(processed)
}

/// Normalize a URL for deduplication
fn normalize_url(url_str: &str) -> Result<String> {
    let mut url = Url::parse(url_str)?;
    
    // Convert scheme and host to lowercase
    if let Some(host) = url.host_str() {
        url.set_host(Some(&host.to_lowercase()))?;
    }
    
    // Sort query parameters
    let mut pairs: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    pairs.sort();
    
    // Rebuild query string with sorted parameters
    if !pairs.is_empty() {
        let query = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        url.set_query(Some(&query));
    }
    
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        assert_eq!(
            normalize_url("https://Example.com/path?b=2&a=1").unwrap(),
            "https://example.com/path?a=1&b=2"
        );
        assert_eq!(
            normalize_url("HTTP://EXAMPLE.COM/Path").unwrap(),
            "http://example.com/Path"
        );
    }
}
