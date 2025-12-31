use anyhow::Result;
use dashmap::DashMap;
use reqwest::{Client, ClientBuilder, Proxy};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// HTTP client with rate limiting and connection pooling
pub struct HttpClient {
    client: Client,
    rate_limiter: Arc<RateLimiter>,
    domain_limiters: Arc<DashMap<String, Arc<RateLimiter>>>,
}

impl HttpClient {
    /// Create a new HTTP client with configuration
    pub fn new(
        timeout: Duration,
        proxy: Option<String>,
        user_agent: String,
        global_rate_limit: u32,
    ) -> Result<Self> {
        let mut builder = ClientBuilder::new()
            .timeout(timeout)
            .user_agent(user_agent)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90));

        if let Some(proxy_url) = proxy {
            builder = builder.proxy(Proxy::all(&proxy_url)?);
        }

        let client = builder.build()?;

        Ok(Self {
            client,
            rate_limiter: Arc::new(RateLimiter::new(global_rate_limit)),
            domain_limiters: Arc::new(DashMap::new()),
        })
    }

    /// Get the underlying reqwest client
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Make a rate-limited GET request
    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        self.request(reqwest::Method::GET, url, None).await
    }

    /// Make a rate-limited POST request
    pub async fn post(&self, url: &str, body: Option<String>) -> Result<reqwest::Response> {
        self.request(reqwest::Method::POST, url, body).await
    }

    /// Make a rate-limited request
    async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<String>,
    ) -> Result<reqwest::Response> {
        // Extract domain for per-domain rate limiting
        let domain = extract_domain(url)?;

        // Wait for global rate limit
        self.rate_limiter.acquire().await;

        // Wait for per-domain rate limit
        let domain_limiter = self
            .domain_limiters
            .entry(domain.clone())
            .or_insert_with(|| Arc::new(RateLimiter::new(10))) // 10 requests per second per domain
            .clone();
        domain_limiter.acquire().await;

        // Make request
        let mut request = self.client.request(method, url);
        if let Some(body_content) = body {
            request = request.body(body_content);
        }

        let response = request.send().await?;

        // Handle rate limiting (429 Too Many Requests)
        if response.status() == 429 {
            tracing::warn!("Rate limited by server for {}, consider reducing rate limit", url);
        }

        Ok(response)
    }
}

/// Token bucket rate limiter
pub struct RateLimiter {
    semaphore: Semaphore,
    rate: u32,
    last_refill: Arc<tokio::sync::Mutex<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter with requests per second
    pub fn new(rate: u32) -> Self {
        Self {
            semaphore: Semaphore::new(rate as usize),
            rate,
            last_refill: Arc::new(tokio::sync::Mutex::new(Instant::now())),
        }
    }

    /// Acquire a token (blocks if rate limit exceeded)
    pub async fn acquire(&self) {
        // Refill tokens if a second has passed
        let mut last_refill = self.last_refill.lock().await;
        let now = Instant::now();
        if now.duration_since(*last_refill) >= Duration::from_secs(1) {
            // Add available permits back
            let available = self.semaphore.available_permits();
            let to_add = (self.rate as usize).saturating_sub(available);
            if to_add > 0 {
                self.semaphore.add_permits(to_add);
            }
            *last_refill = now;
        }
        drop(last_refill);

        // Acquire a permit
        let _ = self.semaphore.acquire().await;
    }
}

/// Extract domain from URL
fn extract_domain(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url)?;
    let domain = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("No host in URL"))?
        .to_string();
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://example.com/path").unwrap(),
            "example.com"
        );
        assert_eq!(
            extract_domain("https://sub.example.com:8080/path").unwrap(),
            "sub.example.com"
        );
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(2);
        let start = Instant::now();

        // Should be able to acquire 2 immediately
        limiter.acquire().await;
        limiter.acquire().await;

        // Third should wait
        limiter.acquire().await;

        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_secs(1));
    }
}
