use anyhow::Result;
use neutron_core::HttpClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct URLScanResponse {
    results: Vec<URLScanResult>,
}

#[derive(Debug, Deserialize)]
struct URLScanResult {
    page: URLScanPage,
}

#[derive(Debug, Deserialize)]
struct URLScanPage {
    url: String,
}

/// Fetch URLs from URLScan.io
pub async fn fetch_urlscan(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from URLScan.io for: {}", domain);
    
    let url = format!("https://urlscan.io/api/v1/search/?q=domain:{}", domain);
    
    match client.get(&url).await {
        Ok(response) => {
            if response.status().is_success() {
                let urlscan_response: URLScanResponse = response.json().await?;
                
                let urls: Vec<String> = urlscan_response.results
                    .into_iter()
                    .map(|result| result.page.url)
                    .filter(|url| url.contains(&domain))
                    .collect();
                
                tracing::info!("URLScan.io found {} URLs", urls.len());
                Ok(urls)
            } else {
                tracing::warn!("URLScan.io returned status: {}", response.status());
                Ok(vec![])
            }
        }
        Err(e) => {
            tracing::warn!("URLScan.io request failed: {}", e);
            Ok(vec![])
        }
    }
}
