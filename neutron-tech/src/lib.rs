use anyhow::Result;
use neutron_types::Technology;
use tracing::{info, warn};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Web servers
    static ref SERVER_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("Apache", Regex::new(r"Apache/?([\d.]+)?").unwrap()),
        ("Nginx", Regex::new(r"nginx/?([\d.]+)?").unwrap()),
        ("Microsoft-IIS", Regex::new(r"Microsoft-IIS/?([\d.]+)?").unwrap()),
        ("LiteSpeed", Regex::new(r"LiteSpeed").unwrap()),
    ];
    
    // Frameworks & CMS
    static ref FRAMEWORK_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("WordPress", Regex::new(r"wp-content|wp-includes").unwrap()),
        ("Drupal", Regex::new(r"/sites/default|Drupal").unwrap()),
        ("Joomla", Regex::new(r"/components/com_|Joomla").unwrap()),
        ("Django", Regex::new(r"csrfmiddlewaretoken|__django__").unwrap()),
        ("Ruby on Rails", Regex::new(r"csrf-token|_rails_").unwrap()),
        ("React", Regex::new(r"react|__REACT").unwrap()),
        ("Angular", Regex::new(r"ng-app|angular").unwrap()),
        ("Vue.js", Regex::new(r"vue|__VUE__").unwrap()),
    ];
    
    // CDN & WAF
    static ref CDN_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("Cloudflare", Regex::new(r"cloudflare|__cfduid|CF-RAY").unwrap()),
        ("Akamai", Regex::new(r"akamai").unwrap()),
        ("Fastly", Regex::new(r"fastly").unwrap()),
        ("AWS CloudFront", Regex::new(r"cloudfront").unwrap()),
    ];
}

pub async fn identify_technologies(url: &str) -> Result<Vec<Technology>> {
    info!("Identifying technologies for: {}", url);
    
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    
    let response = client.get(url).send().await?;
    let headers = response.headers().clone();
    let body = response.text().await?;
    
    let mut technologies = Vec::new();
    
    // Check HTTP headers
    if let Some(server) = headers.get("server") {
        if let Ok(server_str) = server.to_str() {
            for (name, pattern) in SERVER_PATTERNS.iter() {
                if let Some(captures) = pattern.captures(server_str) {
                    let version = captures.get(1).map(|m| m.as_str().to_string());
                    technologies.push(Technology {
                        name: name.to_string(),
                        version,
                        category: "Web Server".to_string(),
                        confidence: 100,
                    });
                }
            }
        }
    }
    
    if let Some(powered_by) = headers.get("x-powered-by") {
        if let Ok(powered_str) = powered_by.to_str() {
            technologies.push(Technology {
                name: powered_str.to_string(),
                version: None,
                category: "Framework".to_string(),
                confidence: 90,
            });
        }
    }
    
    // Check for CDN/WAF in headers
    for (name, pattern) in CDN_PATTERNS.iter() {
        let headers_str = format!("{:?}", headers);
        if pattern.is_match(&headers_str) {
            technologies.push(Technology {
                name: name.to_string(),
                version: None,
                category: "CDN/WAF".to_string(),
                confidence: 85,
            });
        }
    }
    
    // Check HTML body for frameworks/CMS
    for (name, pattern) in FRAMEWORK_PATTERNS.iter() {
        if pattern.is_match(&body) {
            technologies.push(Technology {
                name: name.to_string(),
                version: None,
                category: "Framework/CMS".to_string(),
                confidence: 75,
            });
        }
    }
    
    // Extract JS libraries from script tags
    let script_regex = Regex::new(r#"<script[^>]*src=["']([^"']+)["']"#).unwrap();
    for captures in script_regex.captures_iter(&body) {
        if let Some(src) = captures.get(1) {
            let src_str = src.as_str();
            if src_str.contains("jquery") {
                let version_regex = Regex::new(r"jquery-?([\d.]+)").unwrap();
                let version = version_regex.captures(src_str)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string());
                technologies.push(Technology {
                    name: "jQuery".to_string(),
                    version,
                    category: "JavaScript Library".to_string(),
                    confidence: 95,
                });
            }
        }
    }
    
    info!("Technology fingerprinting complete: {} technologies identified", technologies.len());
    Ok(technologies)
}
