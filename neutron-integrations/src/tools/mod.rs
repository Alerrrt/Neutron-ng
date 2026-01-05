use anyhow::Result;
use crate::ToolWrapper;
use tracing::info;

pub struct Subfinder(ToolWrapper);

impl Subfinder {
    pub fn new() -> Result<Self> {
        Ok(Self(ToolWrapper::new("subfinder")?))
    }

    pub async fn run(&self, domain: &str) -> Result<Vec<String>> {
        info!("Running Subfinder on {}", domain);
        // subfinder -d example.com -silent
        let args = ["-d", domain, "-silent"];
        let output = self.0.run(&args, None).await?;
        
        Ok(output.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }
}

pub struct Naabu(ToolWrapper);

impl Naabu {
    pub fn new() -> Result<Self> {
        Ok(Self(ToolWrapper::new("naabu")?))
    }

    pub async fn run(&self, host: &str) -> Result<Vec<u16>> {
        info!("Running Naabu on {}", host);
        // naabu -host example.com -silent -json
        let args = ["-host", host, "-silent", "-json"];
        let output = self.0.run(&args, None).await?;
        
        // Parse basic output or JSON if we wanted detailed fields
        // For simple integration, let's just grab ports from text output if standard
        // But we used -json. Let's parse JSON lines.
        
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

pub struct Httpx(ToolWrapper);

impl Httpx {
    pub fn new() -> Result<Self> {
        Ok(Self(ToolWrapper::new("httpx")?))
    }

    pub async fn run(&self, targets: &[String]) -> Result<Vec<String>> {
        info!("Running HTTPX on {} targets", targets.len());
        let input = targets.join("\n");
        // httpx -silent -json
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

pub struct Nuclei(ToolWrapper);

impl Nuclei {
    pub fn new() -> Result<Self> {
        Ok(Self(ToolWrapper::new("nuclei")?))
    }

    pub async fn run(&self, targets: &[String], output_dir: &str) -> Result<String> {
        info!("Running Nuclei on {} targets", targets.len());
        let input = targets.join("\n");
        let results_file = format!("{}/nuclei_results.json", output_dir);
        
        // nuclei -silent -json-export results.json
        // Using fewer flags to ensure stability for now
        let args = [
            "-silent",
            "-json-export", &results_file,
            // "-t", "cves", // Can make this configurable later
        ];
        
        let _ = self.0.run(&args, Some(&input)).await?;
        
        Ok(results_file)
    }
}
