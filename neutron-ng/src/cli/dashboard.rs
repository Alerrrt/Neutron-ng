use std::io::{self, Write};
use crate::cli::display;

/// Interactive dashboard for Neutron-ng
pub struct Dashboard {
    api_keys_configured: bool,
}

impl Dashboard {
    pub fn new() -> Self {
        Self {
            api_keys_configured: false,
        }
    }
    
    /// Run the interactive dashboard
    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            self.show_main_menu();
            
            let choice = self.get_input("Enter your choice");
            
            match choice.trim() {
                "1" => {
                    self.configure_api_keys()?;
                }
                "2" => {
                    self.start_scan().await?;
                }
                "3" => {
                    self.show_status();
                }
                "4" => {
                    display::info("Exiting Neutron-ng. Goodbye!");
                    break;
                }
                "" => {
                    // Enter key - start quick scan
                    self.start_scan().await?;
                }
                _ => {
                    display::warning("Invalid choice. Please select 1-4.");
                }
            }
            
            println!("\n");
            self.pause();
        }
        
        Ok(())
    }
    
    fn show_main_menu(&self) {
        display::section_header("NEUTRON-NG INTERACTIVE DASHBOARD");
        
        println!("\n  MAIN MENU:");
        println!("  ┌─────────────────────────────────────────────────────────────────────────┐");
        println!("  │                                                                         │");
        println!("  │  [1] Configure API Keys                                                │");
        println!("  │  [2] Start New Scan                                                    │");
        println!("  │  [3] Show Current Configuration                                        │");
        println!("  │  [4] Exit                                                              │");
        println!("  │                                                                         │");
        println!("  │  Press ENTER for Quick Scan                                            │");
        println!("  │                                                                         │");
        println!("  └─────────────────────────────────────────────────────────────────────────┘");
        
        if self.api_keys_configured {
            display::success("API keys are configured");
        } else {
            display::warning("API keys not configured (some sources will be skipped)");
        }
        
        println!();
    }
    
    fn configure_api_keys(&mut self) -> anyhow::Result<()> {
        display::section_header("API KEY CONFIGURATION");
        
        println!();
        display::info("Configure API keys for enhanced reconnaissance");
        display::info("You can skip any key by pressing Enter");
        println!();
        
        // VirusTotal
        if let Some(_) = display::prompt_api_key("VirusTotal", "NEUTRON_VIRUSTOTAL_API_KEY") {
            // Key configured
        }
        
        // SecurityTrails
        if let Some(_) = display::prompt_api_key("SecurityTrails", "NEUTRON_SECURITYTRAILS_API_KEY") {
            // Key configured
        }
        
        // Chaos
        if let Some(_) = display::prompt_api_key("Project Discovery Chaos", "NEUTRON_CHAOS_API_KEY") {
            // Key configured
        }
        
        self.api_keys_configured = true;
        
        println!();
        display::success("API key configuration complete!");
        
        Ok(())
    }
    
    async fn start_scan(&self) -> anyhow::Result<()> {
        display::section_header("START NEW SCAN");
        
        println!();
        display::info("Enter target domain or URL to scan");
        display::info("Examples: example.com, https://example.com");
        println!();
        
        let target = self.get_input("Target");
        
        if target.trim().is_empty() {
            display::error("Target cannot be empty");
            return Ok(());
        }
        
        println!();
        display::info("Select scan type:");
        println!("  [1] Full Scan (Subdomains + URLs + JavaScript)");
        println!("  [2] Subdomains Only");
        println!("  [3] URLs Only");
        println!("  [4] JavaScript Analysis Only");
        println!();
        
        let scan_type = self.get_input("Scan type (default: 1)");
        let scan_type = if scan_type.trim().is_empty() { "1" } else { &scan_type };
        
        println!();
        let output_dir = self.get_input("Output directory (default: ./results)");
        let output_dir = if output_dir.trim().is_empty() { "./results" } else { &output_dir };
        
        println!();
        display::section_header(&format!("SCANNING: {}", target));
        
        match scan_type.trim() {
            "1" => self.run_full_scan(&target, output_dir).await?,
            "2" => self.run_subdomain_scan(&target).await?,
            "3" => self.run_url_scan(&target).await?,
            "4" => self.run_js_scan(&target).await?,
            _ => {
                display::warning("Invalid scan type, running full scan");
                self.run_full_scan(&target, output_dir).await?;
            }
        }
        
        Ok(())
    }
    
    async fn run_full_scan(&self, target: &str, output_dir: &str) -> anyhow::Result<()> {
        let mut storage = neutron_core::ResultStorage::new(target, Some(output_dir))?;
        display::status("Output Directory", &storage.scan_dir().display().to_string());
        display::status("Scan ID", storage.scan_id());
        
        let mut all_subdomains = Vec::new();
        let mut all_urls = Vec::new();
        let mut all_endpoints = Vec::new();
        let mut all_secrets = Vec::new();
        let mut all_dns_records = Vec::new();
        let mut all_technologies = Vec::new();
        
        // 1. DNS Enumeration
        display::module_header("DNS Intelligence");
        match neutron_dns::enumerate_dns_records(target).await {
            Ok(results) => {
                display::success(&format!("Found {} DNS records", results.len()));
                storage.save_dns_records(&results)?;
                storage.record_module("dns");
                all_dns_records = results;
            }
            Err(e) => {
                display::error(&format!("DNS enumeration failed: {}", e));
            }
        }
        
        // 2. Subdomain enumeration
        display::module_header("Subdomain Enumeration");
        match neutron_subdomain::enumerate_subdomains(target, true, true).await {
            Ok(results) => {
                display::success(&format!("Found {} subdomains", results.len()));
                storage.save_subdomains(&results)?;
                storage.record_module("subdomains");
                all_subdomains = results;
            }
            Err(e) => {
                display::error(&format!("Subdomain enumeration failed: {}", e));
            }
        }
        
        // 3. URL discovery
        display::module_header("URL Discovery");
        match neutron_url::discover_urls(target, true, false).await {
            Ok(results) => {
                display::success(&format!("Found {} URLs", results.len()));
                storage.save_urls(&results)?;
                storage.record_module("urls");
                all_urls = results;
            }
            Err(e) => {
                display::error(&format!("URL discovery failed: {}", e));
            }
        }
        
        // 4. Technology Fingerprinting
        display::module_header("Technology Fingerprinting");
        let tech_url = format!("https://{}", target);
        match neutron_tech::identify_technologies(&tech_url).await {
            Ok(results) => {
                display::success(&format!("Identified {} technologies", results.len()));
                storage.save_technologies(&results)?;
                storage.record_module("technologies");
                all_technologies = results;
            }
            Err(e) => {
                display::error(&format!("Technology fingerprinting failed: {}", e));
            }
        }
        
        // 5. JavaScript analysis
        display::module_header("JavaScript Analysis");
        let js_urls = if !all_urls.is_empty() {
            all_urls.iter().take(5).map(|u| u.url.clone()).collect()
        } else {
            vec![format!("https://{}", target)]
        };
        
        match neutron_js::analyze_javascript(&js_urls).await {
            Ok((endpoints, secrets)) => {
                display::success(&format!("Found {} endpoints, {} secrets", endpoints.len(), secrets.len()));
                storage.save_js_endpoints(&endpoints)?;
                storage.save_secrets(&secrets)?;
                storage.record_module("javascript");
                all_endpoints = endpoints;
                all_secrets = secrets;
            }
            Err(e) => {
                display::error(&format!("JavaScript analysis failed: {}", e));
            }
        }
        
        storage.create_summary(
            all_subdomains.len(),
            all_urls.len(),
            all_endpoints.len(),
            all_secrets.len(),
        )?;
        storage.finalize()?;
        
        display::results_summary(
            all_subdomains.len(),
            all_urls.len(),
            all_endpoints.len(),
            all_secrets.len(),
        );
        
        display::info(&format!("Results saved to: {}", storage.scan_dir().display()));
        display::info("View SUMMARY.txt for detailed report");
        
        Ok(())
    }
    
    async fn run_subdomain_scan(&self, target: &str) -> anyhow::Result<()> {
        match neutron_subdomain::enumerate_subdomains(target, true, true).await {
            Ok(results) => {
                display::success(&format!("Found {} subdomains", results.len()));
                println!();
                display::table_header("Subdomain", "Resolved IPs", "Source");
                for result in results.iter().take(50) {
                    let ips = if result.resolved_ips.is_empty() {
                        "N/A".to_string()
                    } else {
                        result.resolved_ips.join(", ")
                    };
                    display::table_row(&result.subdomain, &ips, &result.source);
                }
                if results.len() > 50 {
                    display::info(&format!("... and {} more subdomains", results.len() - 50));
                }
                display::table_footer();
            }
            Err(e) => {
                display::error(&format!("Enumeration failed: {}", e));
            }
        }
        Ok(())
    }
    
    async fn run_url_scan(&self, target: &str) -> anyhow::Result<()> {
        match neutron_url::discover_urls(target, true, false).await {
            Ok(results) => {
                display::success(&format!("Found {} URLs", results.len()));
                println!();
                for result in results.iter().take(30) {
                    display::info(&format!("{} (source: {})", result.url, result.source));
                }
                if results.len() > 30 {
                    display::info(&format!("... and {} more URLs", results.len() - 30));
                }
            }
            Err(e) => {
                display::error(&format!("URL discovery failed: {}", e));
            }
        }
        Ok(())
    }
    
    async fn run_js_scan(&self, target: &str) -> anyhow::Result<()> {
        let urls = if target.starts_with("http") {
            vec![target.to_string()]
        } else {
            vec![format!("https://{}", target)]
        };
        
        match neutron_js::analyze_javascript(&urls).await {
            Ok((endpoints, secrets)) => {
                display::success("Analysis complete");
                
                if !endpoints.is_empty() {
                    println!();
                    display::module_header(&format!("API Endpoints: {}", endpoints.len()));
                    for endpoint in endpoints.iter().take(20) {
                        display::info(&format!("{} (from: {})", endpoint.endpoint, endpoint.source_url));
                    }
                    if endpoints.len() > 20 {
                        display::info(&format!("... and {} more endpoints", endpoints.len() - 20));
                    }
                }
                
                if !secrets.is_empty() {
                    println!();
                    display::module_header(&format!("Potential Secrets: {}", secrets.len()));
                    for secret in secrets.iter().take(10) {
                        let confidence_pct = (secret.confidence * 100.0) as u32;
                        display::info(&format!("[{}%] {} - {} chars",
                            confidence_pct,
                            secret.secret_type,
                            secret.value.len()
                        ));
                    }
                   if secrets.len() > 10 {
                        display::info(&format!("... and {} more secrets", secrets.len() - 10));
                    }
                    display::warning("Review secrets manually - may contain false positives");
                }
            }
            Err(e) => {
                display::error(&format!("Analysis failed: {}", e));
            }
        }
        Ok(())
    }
    
    fn show_status(&self) {
        display::section_header("CURRENT CONFIGURATION");
        
        println!();
        display::status("VirusTotal API", 
            if std::env::var("NEUTRON_VIRUSTOTAL_API_KEY").is_ok() { "Configured" } else { "Not configured" });
        display::status("SecurityTrails API", 
            if std::env::var("NEUTRON_SECURITYTRAILS_API_KEY").is_ok() { "Configured" } else { "Not configured" });
        display::status("Chaos API", 
            if std::env::var("NEUTRON_CHAOS_API_KEY").is_ok() { "Configured" } else { "Not configured" });
        
        println!();
        display::info("Free sources available:");
        println!("  - cert.sh, crt.sh (Certificate Transparency)");
        println!("  - BufferOver, RapidDNS, Anubis, recon.dev");
        println!("  - Wayback Machine, Common Crawl, AlienVault, URLScan");
        println!("  - JavaScript Analysis (LinkFinder + Secrets Hunter)");
    }
    
    fn get_input(&self, prompt: &str) -> String {
        print!("  [?] {}: ", prompt);
        if let Err(e) = io::stdout().flush() {
            display::error(&format!("I/O error: {}", e));
            return String::new();
        }
        
        let mut input = String::new();
        if let Err(e) = io::stdin().read_line(&mut input) {
            display::error(&format!("Failed to read input: {}", e));
            return String::new();
        }
        input.trim().to_string()
    }
    
    fn pause(&self) {
        print!("\n  Press Enter to continue...");
        let _ = io::stdout().flush(); // Ignore flush errors on pause
        let mut input = String::new();
        let _ = io::stdin().read_line(&mut input); // Ignore read errors on pause
    }
}
