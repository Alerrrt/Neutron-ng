use anyhow::Result;
use neutron_core::HttpClient;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CommonCrawlIndex {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct CommonCrawlResult {
    url: String,
}

/// Fetch URLs from Common Crawl
pub async fn fetch_commoncrawl(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching from Common Crawl for: {}", domain);
    
    // First, get the latest index
    let index_url = "https://index.commoncrawl.org/collinfo.json";
    
    let indices: Vec<CommonCrawlIndex> = match client.get(index_url).await {
        Ok(response) => {
            if response.status().is_success() {
                response.json().await.unwrap_or_else(|_| vec![])
            } else {
                tracing::warn!("Common Crawl index returned status: {}", response.status());
                return Ok(vec![]);
            }
        }
        Err(e) => {
            tracing::warn!("Common Crawl index request failed: {}", e);
            return Ok(vec![]);
        }
    };
    
    if indices.is_empty() {
        tracing::warn!("No Common Crawl indices found");
        return Ok(vec![]);
    }
    
    // Use the most recent index
    let latest_index = &indices[0].id;
    tracing::debug!("Using Common Crawl index: {}", latest_index);
    
    // Query the index for the domain
    let query_url = format!(
        "https://index.commoncrawl.org/{}-index?url=*.{}&output=json",
        latest_index, domain
    );
    
    match client.get(&query_url).await {
        Ok(response) => {
            if response.status().is_success() {
                let text = response.text().await?;
                
                // Common Crawl returns NDJSON (newline-delimited JSON)
                let urls: Vec<String> = text
                    .lines()
                    .filter_map(|line| {
                        serde_json::from_str::<CommonCrawlResult>(line)
                            .ok()
                            .map(|result| result.url)
                    })
                    .filter(|url| url.contains(&domain))
                    .collect();
                
                tracing::info!("Common Crawl found {} URLs", urls.len());
                Ok(urls)
            } else {
                tracing::warn!("Common Crawl query returned status: {}", response.status());
                Ok(vec![])
            }
        }
        Err(e) => {
            tracing::warn!("Common Crawl query failed: {}", e);
            Ok(vec![])
        }
    }
}
