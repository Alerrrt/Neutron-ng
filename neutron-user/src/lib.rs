use neutron_types::UserResult;
use serde::Deserialize;
use tracing::{info, debug};
use neutron_core::HttpClient;

#[derive(Debug, Deserialize, Clone)]
pub struct SiteData {
    pub name: String,
    pub url: String,
    pub error_type: String, // "status_code" or "message"
    pub error_msg: Option<String>,
    pub category: Option<String>,
}

pub struct UserSearchEngine {
    sites: Vec<SiteData>,
    client: HttpClient,
}

impl UserSearchEngine {
    pub fn new() -> Result<Self> {
        let client = HttpClient::new(
            std::time::Duration::from_secs(10),
            None,
            format!("Neutron-ng/{}", env!("CARGO_PKG_VERSION")),
            20, // Lower concurrency for user search to avoid blocking
        )?;
        
        // In a real implementation, this would load from a JSON file
        let sites = load_sites();
        
        Ok(Self {
            sites,
            client,
        })
    }
    
    pub async fn search_username(&self, username: &str) -> Result<Vec<UserResult>> {
        info!("Searching for username '{}' across {} platforms", username, self.sites.len());
        
        let mut results = Vec::new();
        let mut futures = Vec::new();
        
        for site in &self.sites {
            let site = site.clone();
            let username = username.to_string();
            let client = self.client.clone();
            
            futures.push(tokio::spawn(async move {
                check_site(&client, &site, &username).await
            }));
        }
        
        for future in futures {
            if let Ok(Ok(Some(result))) = future.await {
                results.push(result);
            }
        }
        
        info!("Found {} profiles for '{}'", results.len(), username);
        Ok(results)
    }
}

async fn check_site(client: &HttpClient, site: &SiteData, username: &str) -> Result<Option<UserResult>> {
    let url = site.url.replace("{}", username);
    debug!("Checking {}", url);
    
    match client.get(&url).await {
        Ok(response) => {
            let status = response.status();
            let mut exists = false;
            
            if site.error_type == "status_code" {
                if status.is_success() {
                    exists = true;
                }
            } else if site.error_type == "message" {
                if status.is_success() {
                    let text = response.text().await.unwrap_or_default();
                    if let Some(msg) = &site.error_msg {
                        if !text.contains(msg) {
                            exists = true;
                        }
                    }
                }
            }
            
            if exists {
                return Ok(Some(UserResult {
                    username: username.to_string(),
                    platform: site.name.clone(),
                    url,
                    exists: true,
                    category: site.category.clone(),
                }));
            }
        }
        Err(_) => {
            // Ignore connection errors
        }
    }
    
    Ok(None)
}

fn load_sites() -> Vec<SiteData> {
    // A small sample of sites for MVP. 
    // In production, this should be a large JSON list (e.g. from Sherlock/Maigret)
    vec![
        SiteData {
            name: "GitHub".to_string(),
            url: "https://github.com/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Coding".to_string()),
        },
        SiteData {
            name: "Twitter".to_string(),
            url: "https://twitter.com/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Social".to_string()),
        },
        SiteData {
            name: "Instagram".to_string(),
            url: "https://instagram.com/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Social".to_string()),
        },
        SiteData {
            name: "Reddit".to_string(),
            url: "https://www.reddit.com/user/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Social".to_string()),
        },
        SiteData {
            name: "Docker Hub".to_string(),
            url: "https://hub.docker.com/u/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Coding".to_string()),
        },
        SiteData {
            name: "GitLab".to_string(),
            url: "https://gitlab.com/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Coding".to_string()),
        },
        SiteData {
            name: "BitBucket".to_string(),
            url: "https://bitbucket.org/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Coding".to_string()),
        },
        SiteData {
            name: "Medium".to_string(),
            url: "https://medium.com/@{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Blogging".to_string()),
        },
        SiteData {
            name: "Dev.to".to_string(),
            url: "https://dev.to/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Coding".to_string()),
        },
        SiteData {
            name: "HackerOne".to_string(),
            url: "https://hackerone.com/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Security".to_string()),
        },
        SiteData {
            name: "Bugcrowd".to_string(),
            url: "https://bugcrowd.com/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Security".to_string()),
        },
         SiteData {
            name: "Pastebin".to_string(),
            url: "https://pastebin.com/u/{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Utility".to_string()),
        },
        SiteData {
            name: "Wikipedia".to_string(),
            url: "https://en.wikipedia.org/wiki/User:{}".to_string(),
            error_type: "status_code".to_string(),
            error_msg: None,
            category: Some("Knowledge".to_string()),
        },
        SiteData {
            name: "Steam".to_string(),
            url: "https://steamcommunity.com/id/{}".to_string(),
            error_type: "message".to_string(),
            error_msg: Some("The specified profile could not be found".to_string()),
            category: Some("Gaming".to_string()),
        }
    ]
}
