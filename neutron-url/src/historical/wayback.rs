use anyhow::Result;
use neutron_core::HttpClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct WaybackResponse(Vec<Vec<String>>);

/// Fetch URLs from Wayback Machine CDX API
pub async fn fetch_wayback(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from Wayback Machine for: {}", domain);
    
    // Wayback CDX API endpoint
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey",
        domain
    );
    
    match client.get(&url).await {
        Ok(response) => {
            if response.status().is_success() {
                let text = response.text().await?;
                
                // Parse JSON response - array of arrays
                let wayback_data: WaybackResponse = serde_json::from_str(&text)
                    .unwrap_or(WaybackResponse(vec![]));
                
                // Skip first row (headers) and extract URLs
                let urls: Vec<String> = wayback_data.0
                    .into_iter()
                    .skip(1)
                    .filter_map(|row| row.get(0).cloned())
                    .filter(|url| url.contains(&domain))
                    .collect();
                
                tracing::info!("Wayback Machine found {} URLs", urls.len());
                Ok(urls)
            } else {
                tracing::warn!("Wayback Machine returned status: {}", response.status());
                Ok(vec![])
            }
        }
        Err(e) => {
            tracing::warn!("Wayback Machine request failed: {}", e);
            Ok(vec![])
        }
    }
}
