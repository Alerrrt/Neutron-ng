use anyhow::Result;
use neutron_core::HttpClient;
use scraper::{Html, Selector};
use std::collections::HashSet;

/// JavaScript file representation
#[derive(Debug, Clone)]
pub struct JsFile {
    pub url: String,
    pub content: String,
}

/// Discover JavaScript files from HTML pages
pub async fn discover_js_files(urls: &[String]) -> Result<Vec<JsFile>> {
    tracing::info!("Discovering JavaScript files from {} URLs", urls.len());
    
    let http_client = HttpClient::new(
        std::time::Duration::from_secs(30),
        None,
        format!("Neutron-ng/{}", env!("CARGO_PKG_VERSION")),
        50,
    )?;
    
    let mut js_files = Vec::new();
    let mut discovered_urls = HashSet::new();
    
    for url in urls.iter().take(10) { // Limit to first 10 URLs for now
        // Fetch the HTML page
        match http_client.get(url).await {
            Ok(response) => {
                if response.status().is_success() {
                    let html = response.text().await?;
                    
                    // Extract JavaScript URLs from script tags
                    let js_urls = extract_js_urls(&html, url);
                    
                    for js_url in js_urls {
                        if discovered_urls.insert(js_url.clone()) {
                            // Fetch the JavaScript file
                            if let Ok(js_content) = fetch_js_file(&js_url, &http_client).await {
                                js_files.push(JsFile {
                                    url: js_url,
                                    content: js_content,
                                });
                            }
                        }
                    }
                    
                    // Also extract inline scripts
                    let inline_scripts = extract_inline_scripts(&html);
                    for (idx, script) in inline_scripts.into_iter().enumerate() {
                        js_files.push(JsFile {
                            url: format!("{}#inline-{}", url, idx),
                            content: script,
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to fetch {}: {}", url, e);
            }
        }
    }
    
    tracing::info!("Discovered {} JavaScript files", js_files.len());
    Ok(js_files)
}

/// Extract JavaScript URLs from HTML
fn extract_js_urls(html: &str, base_url: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let script_selector = Selector::parse("script[src]").unwrap();
    
    let mut urls = Vec::new();
    
    for element in document.select(&script_selector) {
        if let Some(src) = element.value().attr("src") {
            // Resolve relative URLs
            if let Ok(absolute_url) = resolve_url(base_url, src) {
                if absolute_url.ends_with(".js") || src.contains(".js") {
                    urls.push(absolute_url);
                }
            }
        }
    }
    
    urls
}

/// Extract inline JavaScript from HTML
fn extract_inline_scripts(html: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let script_selector = Selector::parse("script:not([src])").unwrap();
    
    let mut scripts = Vec::new();
    
    for element in document.select(&script_selector) {
        let script_content = element.text().collect::<String>();
        if !script_content.trim().is_empty() {
            scripts.push(script_content);
        }
    }
    
    scripts
}

/// Fetch JavaScript file content
async fn fetch_js_file(url: &str, client: &HttpClient) -> Result<String> {
    tracing::debug!("Fetching JavaScript file: {}", url);
    
    match client.get(url).await {
        Ok(response) => {
            if response.status().is_success() {
                Ok(response.text().await?)
            } else {
                Err(anyhow::anyhow!("HTTP {}", response.status()))
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// Resolve relative URL to absolute
fn resolve_url(base: &str, relative: &str) -> Result<String> {
    let base_url = url::Url::parse(base)?;
    let resolved = base_url.join(relative)?;
    Ok(resolved.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_url() {
        assert_eq!(
            resolve_url("https://example.com/page", "/assets/app.js").unwrap(),
            "https://example.com/assets/app.js"
        );
        assert_eq!(
            resolve_url("https://example.com/page", "app.js").unwrap(),
            "https://example.com/app.js"
        );
    }
}
