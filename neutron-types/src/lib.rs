use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Common result type for scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub module: ModuleType,
    pub timestamp: DateTime<Utc>,
    pub data: ResultData,
}

/// Module types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleType {
    Subdomain,
    Url,
    JavaScript,
    Vulnerability,
    Cloud,
    Git,
}

/// Result data variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ResultData {
    Subdomain(SubdomainResult),
    Url(UrlResult),
    JsEndpoint(JsEndpointResult),
    Secret(SecretResult),
    Vulnerability(VulnerabilityResult),
    CloudResource(CloudResourceResult),
}

/// Subdomain discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub source: String,
    pub resolved_ips: Vec<String>,
    pub is_wildcard: bool,
}

/// URL discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlResult {
    pub url: String,
    pub source: String,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
}

/// JavaScript endpoint result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsEndpointResult {
    pub endpoint: String,
    pub source_url: String,
    pub method: Option<String>,
}

/// Secret detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretResult {
    pub secret_type: String,
    pub value: String,
    pub source_url: String,
    pub confidence: f32,
}

/// Vulnerability result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityResult {
    pub vuln_type: VulnerabilityType,
    pub url: String,
    pub parameter: Option<String>,
    pub payload: String,
    pub evidence: String,
    pub severity: Severity,
}

/// Vulnerability types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilityType {
    Xss,
    SqlInjection,
    Lfi,
    Rfi,
    OpenRedirect,
    Cors,
    Ssrf,
    CommandInjection,
    Ssti,
}

/// Severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Cloud resource result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResourceResult {
    pub resource_type: CloudResourceType,
    pub name: String,
    pub url: String,
    pub is_public: bool,
    pub permissions: Vec<String>,
}

/// Cloud resource types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudResourceType {
    AwsS3,
    AzureBlob,
    GcpStorage,
}

/// Scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub id: Uuid,
    pub targets: Vec<String>,
    pub modules: Vec<ModuleType>,
    pub output_dir: String,
    pub output_formats: Vec<OutputFormat>,
    pub concurrency: usize,
    pub timeout: u64,
    pub rate_limit: u32,
}

/// Output formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Csv,
    Html,
    Console,
}

/// Scan status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
}

/// Scan metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub id: Uuid,
    pub status: ScanStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub targets: Vec<String>,
    pub modules: Vec<ModuleType>,
}

/// DNS record result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub domain: String,
}

/// Technology fingerprinting result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub confidence: u8,
}

/// Network intelligence result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIntelligence {
    pub domain: String,
    pub asn_numbers: Vec<String>,
    pub ip_ranges: Vec<String>,
    pub reverse_dns: Vec<String>,
    pub related_domains: Vec<String>,
}

/// User profile result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResult {
    pub username: String,
    pub platform: String,
    pub url: String,
    pub exists: bool,
    pub category: Option<String>,
}
