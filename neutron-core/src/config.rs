use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use anyhow::Result;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub api_keys: HashMap<String, String>,
    pub modules: ModuleConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
    
    pub proxy: Option<String>,
    
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    #[serde(default)]
    pub enabled: Vec<String>,
    
    #[serde(default)]
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_format")]
    pub default_format: String,
    
    #[serde(default = "default_directory")]
    pub directory: PathBuf,
}

// Default values
fn default_timeout() -> u64 {
    30
}

fn default_concurrency() -> usize {
    50
}

fn default_rate_limit() -> u32 {
    100
}

fn default_user_agent() -> String {
    format!("Neutron-ng/{}", env!("CARGO_PKG_VERSION"))
}

fn default_format() -> String {
    "json".to_string()
}

fn default_directory() -> PathBuf {
    PathBuf::from("./results")
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                timeout: default_timeout(),
                concurrency: default_concurrency(),
                rate_limit: default_rate_limit(),
                proxy: None,
                user_agent: default_user_agent(),
            },
            api_keys: HashMap::new(),
            modules: ModuleConfig {
                enabled: vec![],
                disabled: vec![],
            },
            output: OutputConfig {
                default_format: default_format(),
                directory: default_directory(),
            },
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration with environment variable overrides
    pub fn load() -> Result<Self> {
        // Try to load from default locations
        let config_paths = vec![
            "./neutron-ng.toml",
            "~/.config/neutron-ng/config.toml",
            "/etc/neutron-ng/config.toml",
        ];

        let mut config = Config::default();

        for path in config_paths {
            if let Ok(loaded) = Self::from_file(path) {
                config = loaded;
                break;
            }
        }

        // Override with environment variables
        if let Ok(timeout) = std::env::var("NEUTRON_TIMEOUT") {
            if let Ok(timeout) = timeout.parse() {
                config.general.timeout = timeout;
            }
        }

        if let Ok(concurrency) = std::env::var("NEUTRON_CONCURRENCY") {
            if let Ok(concurrency) = concurrency.parse() {
                config.general.concurrency = concurrency;
            }
        }

        // Load API keys from environment
        for (key, value) in std::env::vars() {
            if key.starts_with("NEUTRON_") && key.ends_with("_API_KEY") {
                let service = key
                    .strip_prefix("NEUTRON_")
                    .unwrap()
                    .strip_suffix("_API_KEY")
                    .unwrap()
                    .to_lowercase();
                config.api_keys.insert(service, value);
            }
        }

        Ok(config)
    }

    /// Get API key for a service
    pub fn get_api_key(&self, service: &str) -> Option<&String> {
        self.api_keys.get(service)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.general.timeout, 30);
        assert_eq!(config.general.concurrency, 50);
        assert_eq!(config.general.rate_limit, 100);
    }

    #[test]
    fn test_user_agent() {
        let config = Config::default();
        assert!(config.general.user_agent.starts_with("Neutron-ng/"));
    }
}
