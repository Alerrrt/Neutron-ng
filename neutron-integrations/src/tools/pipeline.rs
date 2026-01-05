use anyhow::Result;
use crate::ToolWrapper;
use std::path::PathBuf;
use tracing::{info, warn};
use std::fs;

/// Comprehensive ProjectDiscovery tools pipeline orchestrator
pub struct PdPipeline {
    target: String,
    output_base: PathBuf,
}

impl PdPipeline {
    pub fn new(target: String, output_base: PathBuf) -> Self {
        Self { target, output_base }
    }
    
    /// Run the full 4-phase reconnaissance pipeline
    /// Note: Nuclei scanning is separate (AI-powered functionality)
    pub async fn run_full_pipeline(&self) -> Result<PipelineResults> {
        info!("🚀 Starting comprehensive PD tools pipeline for: {}", self.target);
        
        let mut results = PipelineResults::default();
        
        // Phase 1: Subdomain Discovery
        info!("📡 Phase 1/4: Subdomain Discovery (subfinder)");
        let subdomains = self.phase1_subdomain_discovery().await?;
        results.subdomains_found = subdomains.len();
        info!("✓ Found {} unique subdomains", subdomains.len());
        
        if subdomains.is_empty() {
            warn!("No subdomains found, skipping remaining phases");
            return Ok(results);
        }
        
        // Phase 2: Port Scanning
        info!("🔍 Phase 2/4: Port Scanning (naabu)");
        let live_hosts = self.phase2_port_scanning(&subdomains).await?;
        results.live_hosts_found = live_hosts.len();
        info!("✓ Found {} live hosts with open ports", live_hosts.len());
        
        if live_hosts.is_empty() {
            warn!("No live hosts found, skipping HTTP phases");
            return Ok(results);
        }
        
        // Phase 3: HTTP Probing
        info!("🌐 Phase 3/4: HTTP Probing (httpx)");
        let live_urls = self.phase3_http_probing(&live_hosts).await?;
        results.live_urls_found = live_urls.len();
        info!("✓ Found {} live HTTP/HTTPS services", live_urls.len());
        
        if live_urls.is_empty() {
            warn!("No live URLs found, skipping crawl phase");
            return Ok(results);
        }
        
        // Phase 4: Web Crawling
        info!("🕷️  Phase 4/4: Web Crawling (katana)");
        let endpoints = self.phase4_web_crawling(&live_urls).await?;
        results.endpoints_found = endpoints.len();
        info!("✓ Discovered {} unique endpoints", endpoints.len());
        
        info!("✅ Pipeline complete! Nuclei scanning available separately via AI scan command");
        Ok(results)
    }
    
    async fn phase1_subdomain_discovery(&self) -> Result<Vec<String>> {
        let phase_dir = self.output_base.join("01_subdomains");
        fs::create_dir_all(&phase_dir)?;
        
        let output_file = phase_dir.join("subfinder_output.txt");
        let subfinder = ToolWrapper::new("subfinder")?;
        
        let _output = subfinder.run(&[
            "-d", &self.target,
            "-all",              // Use all sources
            "-silent",
            "-o", output_file.to_str().unwrap(),
        ], None).await?;
        
        // Read and deduplicate
        let content = fs::read_to_string(&output_file)?;
        let mut subdomains: Vec<String> = content.lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        subdomains.sort();
        subdomains.dedup();
        
        // Save deduplicated list
        let final_file = phase_dir.join("all_subdomains.txt");
        fs::write(&final_file, subdomains.join("\n"))?;
        println!("  💾 Saved {} subdomains to: {}", subdomains.len(), final_file.display());
        
        Ok(subdomains)
    }
    
    async fn phase2_port_scanning(&self, subdomains: &[String]) -> Result<Vec<String>> {
        let phase_dir = self.output_base.join("02_ports");
        fs::create_dir_all(&phase_dir)?;
        
        // Create input file
        let input_file = phase_dir.join("targets.txt");
        fs::write(&input_file, subdomains.join("\n"))?;
        
        let output_file = phase_dir.join("naabu_output.txt");
        let naabu = ToolWrapper::new("naabu")?;
        
        let _output = naabu.run(&[
            "-list", input_file.to_str().unwrap(),
            "-top-ports", "1000",       // Top 1000 ports
            "-c", "50",                  // 50 concurrent hosts
            "-rate", "1000",             // 1000 packets/sec
            "-silent",
            "-o", output_file.to_str().unwrap(),
        ], None).await?;
        
        // Parse results (format: host:port)
        let content = fs::read_to_string(&output_file).unwrap_or_default();
        let live_hosts: Vec<String> = content.lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        
        let final_file = phase_dir.join("live_hosts.txt");
        fs::write(&final_file, live_hosts.join("\n"))?;
        println!("  💾 Saved {} live hosts to: {}", live_hosts.len(), final_file.display());
        
        Ok(live_hosts)
    }
    
    async fn phase3_http_probing(&self, hosts: &[String]) -> Result<Vec<String>> {
        let phase_dir = self.output_base.join("03_http");
        fs::create_dir_all(&phase_dir)?;
        
        // Extract just the hosts (remove port numbers)
        let unique_hosts: Vec<String> = hosts.iter()
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        
        let input_file = phase_dir.join("hosts.txt");
        fs::write(&input_file, unique_hosts.join("\n"))?;
        
        let output_file = phase_dir.join("httpx_output.txt");
        let httpx = ToolWrapper::new("httpx")?;
        
        let _output = httpx.run(&[
            "-list", input_file.to_str().unwrap(),
            "-silent",
            "-follow-redirects",
            "-status-code",
            "-tech-detect",
            "-title",
            "-o", output_file.to_str().unwrap(),
        ], None).await?;
        
        let content = fs::read_to_string(&output_file).unwrap_or_default();
        let live_urls: Vec<String> = content.lines()
            .filter_map(|line| {
                // Extract URL from httpx output
                line.split_whitespace().next().map(|s| s.to_string())
            })
            .collect();
        
        let final_file = phase_dir.join("live_urls.txt");
        fs::write(&final_file, live_urls.join("\n"))?;
        println!("  💾 Saved {} live URLs to: {}", live_urls.len(), final_file.display());
        
        Ok(live_urls)
    }
    
    async fn phase4_web_crawling(&self, urls: &[String]) -> Result<Vec<String>> {
        let phase_dir = self.output_base.join("04_crawl");
        fs::create_dir_all(&phase_dir)?;
        
        let input_file = phase_dir.join("urls.txt");
        fs::write(&input_file, urls.join("\n"))?;
        
        let output_file = phase_dir.join("katana_output.txt");
        let katana = ToolWrapper::new("katana")?;
        
        let _output = katana.run(&[
            "-list", input_file.to_str().unwrap(),
            "-d", "3",                   // Depth 3
            "-jc",                       // JS crawling
            "-kf", "all",                // All known files
            "-silent",
            "-o", output_file.to_str().unwrap(),
        ], None).await?;
        
        let content = fs::read_to_string(&output_file).unwrap_or_default();
        let mut endpoints: Vec<String> = content.lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        endpoints.sort();
        endpoints.dedup();
        
        let final_file = phase_dir.join("all_endpoints.txt");
        fs::write(&final_file, endpoints.join("\n"))?;
        println!("  💾 Saved {} endpoints to: {}", endpoints.len(), final_file.display());
        
        Ok(endpoints)
    }
}

#[derive(Default, Debug)]
pub struct PipelineResults {
    pub subdomains_found: usize,
    pub live_hosts_found: usize,
    pub live_urls_found: usize,
    pub endpoints_found: usize,
}
