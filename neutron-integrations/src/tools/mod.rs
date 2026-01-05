use anyhow::Result;
use crate::ToolWrapper;
use tracing::info;

pub mod pipeline;
pub use pipeline::{PdPipeline, PipelineResults};

// Keep tools simple and inline for now
pub struct Subfinder(ToolWrapper);
pub struct Naabu(ToolWrapper);
pub struct Httpx(ToolWrapper);
pub struct Nuclei(ToolWrapper);
pub struct Katana(ToolWrapper);

impl Subfinder {
    pub fn new() -> Result<Self> {
        Ok(Self(ToolWrapper::new("subfinder")?))
    }

    pub async fn run(&self, domain: &str) -> Result<Vec<String>> {
        info!("Running Subfinder on {}", domain);
        let args = ["-d", domain, "-silent"];
        let output = self.0.run(&args, None).await?;
        
        Ok(output.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }
}

impl Naabu {
    pub fn new() -> Result<Self> {
        Ok(Self(ToolWrapper::new("naabu")?))
    }

    pub async fn run(&self, host: &str) -> Result<Vec<u16>> {
        info!("Running Naabu on {}", host);
        let args = ["-host", host, "-silent", "-json"];
        let output = self.0.run(&args, None).await?;
        
        let mut ports = Vec::new();
        for line in output.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                 if let Some(port) = json["port"].as_u64() {
                     ports.push(port as u16);
                 }
            }
        }
        Ok(ports)
    }
}

impl Httpx {
    pub fn new() -> Result<Self> {
        Ok(Self(ToolWrapper::new("httpx")?))
    }

    pub async fn run(&self, targets: &[String]) -> Result<Vec<String>> {
        info!("Running HTTPX on {} targets", targets.len());
        let input = targets.join("\n");
        let args = ["-silent", "-json"];
        let output = self.0.run(&args, Some(&input)).await?;
        
        let mut results = Vec::new();
        for line in output.lines() {
             if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                 if let Some(url) = json["url"].as_str() {
                     results.push(url.to_string());
                 }
             }
        }
        Ok(results)
    }
}

impl Nuclei {
    pub fn new() -> Result<Self> {
        Ok(Self(ToolWrapper::new("nuclei")?))
    }

    pub async fn run(&self, targets: &[String], output_dir: &str) -> Result<String> {
        info!("Running Nuclei on {} targets", targets.len());
        let input = targets.join("\n");
        let results_file = format!("{}/nuclei_results.json", output_dir);
        
        let args = [
            "-silent",
            "-json-export", &results_file,
        ];
        
        let _ = self.0.run(&args, Some(&input)).await?;
        
        Ok(results_file)
    }
}

impl Katana {
    pub fn new() -> Result<Self> {
        Ok(Self(ToolWrapper::new("katana")?))
    }

    pub async fn run(&self, urls: &[String]) -> Result<Vec<String>> {
        info!("Running Katana on {} URLs", urls.len());
        let input = urls.join("\n");
        let args = ["-silent", "-d", "3", "-jc"];
        let output = self.0.run(&args, Some(&input)).await?;
        
        Ok(output.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }
}
