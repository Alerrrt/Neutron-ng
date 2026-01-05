use anyhow::Result;
use neutron_core::HttpClient;
use serde::Deserialize;

#[derive(Deserialize)]
struct PhonebookResponse {
    #[serde(rename = "results")]
    results: Vec<PhonebookResult>,
}

#[derive(Deserialize)]
struct PhonebookResult {
    domain: String,
}

/// Fetch subdomains from phonebook.cz
pub async fn fetch_phonebook(domain: String, client: HttpClient) -> Result<Vec<String>> {
    tracing::debug!("Fetching subdomains from phonebook.cz for: {}", domain);
    
    // Phonebook.cz API endpoint
    let url = format!("https://phonebook.cz/api/search?domain={}", domain);
    
    let response = client.get(&url).await?;
    
    if !response.status().is_success() {
        anyhow::bail!("phonebook.cz returned status: {}", response.status());
    }
    
    let data: PhonebookResponse = response.json().await?;
    
    let subdomains: Vec<String> = data.results
        .into_iter()
        .map(|result| result.domain)
        .filter(|subdomain| subdomain.ends_with(&format!(".{}", domain)) || subdomain == &domain)
        .collect();
    
    tracing::debug!("phonebook.cz found {} subdomains", subdomains.len());
    Ok(subdomains)
}
