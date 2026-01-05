use std::io::{self, Write};
use crate::cli::display;
use colored::*;

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
            let choice = choice.trim();
            
            match choice {
                "0" => {
                    display::info("Goodbye!");
                    break;
                }
                "1" => self.run_subdomain_scan(true).await?,
                "2" => self.run_url_discovery().await?,
                "3" => self.run_dns_scan().await?,
                "4" => self.run_tech_scan().await?,
                "5" => self.run_network_intel().await?,
                "6" => self.run_js_endpoint_extraction().await?,
                "7" => self.run_secret_scanning().await?,
                "8" => self.run_vulnerability_scan().await?,
                "9" => self.run_ai_scan().await?,
                "10" => self.run_web_crawler().await?,
                "11" => self.run_username_osint().await?,
                "12" => self.run_ip_intelligence().await?,
                "13" => self.configure_api_keys()?,
                "14" => self.setup_tools()?,
                "" => continue,
                _ => {
                    display::warning(&format!("Invalid option: {}", choice));
                }
            }
            
            println!("\n");
            self.pause();
        }
        
        Ok(())
    }
    
    fn show_main_menu(&self) {
        println!("\n{}", "═".repeat(60).bright_cyan());
        println!("{}", "  NEUTRON-NG INTERACTIVE MODE".bright_green().bold());
        println!("{}", "═".repeat(60).bright_cyan());
        
        println!("\n{}", "  RECONNAISSANCE".bright_yellow().bold());
        println!("  {} Subdomain Discovery", "1.".bright_cyan());
        println!("  {} URL Discovery", "2.".bright_cyan());
        println!("  {} DNS Records", "3.".bright_cyan());
        println!("  {} Technology Fingerprinting", "4.".bright_cyan());
        println!("  {} Network Intelligence", "5.".bright_cyan());
        
        println!("\n{}", "  SCANNING".bright_yellow().bold());
        println!("  {} JavaScript Analysis", "6.".bright_cyan());
        println!("  {} Secret Scanning", "7.".bright_cyan());
        println!("  {} Vulnerability Scan", "8.".bright_cyan());
        println!("  {} AI Scan", "9.".bright_cyan());
        
        println!("\n{}", "  CRAWLER & OSINT".bright_yellow().bold());
        println!("  {} Web Crawler", "10.".bright_cyan());
        println!("  {} Username OSINT", "11.".bright_cyan());
        println!("  {} IP Intelligence", "12.".bright_cyan());
        
        println!("\n{}", "  SETUP".bright_yellow().bold());
        println!("  {} Configure API Keys", "13.".bright_cyan());
        println!("  {} Setup Tools", "14.".bright_cyan());
        
        println!("\n  {}  Exit", "0.".bright_red());
        println!("{}", "═".repeat(60).bright_cyan());
        print!("  Choice: ");
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
            "2" => {
                // Subdomain scan only
                let target_str = target.clone();
                display::module_header("Subdomain Enumeration");
                match neutron_subdomain::enumerate_subdomains(&target_str, true, true).await {
                    Ok(results) => {
                        display::success(&format!("Found {} subdomains", results.len()));
                    }
                    Err(e) => display::error(&format!("Scan failed: {}", e)),
                }
            }
            "3" => {
                // URL discovery only 
                display::module_header("URL Discovery");
                match neutron_url::discover_urls(&target, true, false).await {
                    Ok(results) => {
                        display::success(&format!("Found {} URLs", results.len()));
                    }
                    Err(e) => display::error(&format!("Discovery failed: {}", e)),
                }
            }
            "4" => {
                // JS analysis only
                display::module_header("JavaScript Analysis");
                let urls = vec![format!("https://{}", target)];
                match neutron_js::analyze_javascript(&urls).await {
                    Ok((endpoints, secrets)) => {
                        display::success(&format!("Found {} endpoints, {} secrets", endpoints.len(), secrets.len()));
                    }
                    Err(e) => display::error(&format!("Analysis failed: {}", e)),
                }
            }
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
        let mut _all_dns_records = Vec::new();
        let mut _all_technologies = Vec::new();
        
        // 1. DNS Enumeration
        display::module_header("DNS Intelligence");
        match neutron_dns::enumerate_dns_records(target).await {
            Ok(results) => {
                display::success(&format!("Found {} DNS records", results.len()));
                storage.save_dns_records(&results)?;
                storage.record_module("dns");
                _all_dns_records = results;
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
                _all_technologies = results;
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
        let _ = io::stdout().flush();
        let mut input = String::new();
        let _ = io::stdin().read_line(&mut input);
    }
    
    // Individual capability handlers
    
    async fn run_subdomain_scan(&self, use_active: bool) -> anyhow::Result<()> {
        let target = self.get_input("Enter target domain");
        if target.is_empty() { return Ok(()); }
        
        display::section_header(&format!("SUBDOMAIN ENUMERATION: {}", target));
        
        match neutron_subdomain::enumerate_subdomains(&target, true, use_active).await {
            Ok(subdomains) => {
                display::success(&format!("Found {} unique subdomains", subdomains.len()));
                println!();
                for (idx, sd) in subdomains.iter().take(50).enumerate() {
                    println!("  {}. {} (via {})", idx + 1, sd.subdomain, sd.source);
                }
                if subdomains.len() > 50 {
                    display::info(&format!("... and {} more subdomains", subdomains.len() - 50));
                }
            }
            Err(e) => display::error(&format!("Scan failed: {}", e)),
        }
        Ok(())
    }
    
    async fn run_url_discovery(&self) -> anyhow::Result<()> {
        let target = self.get_input("Enter target domain");
        if target.is_empty() { return Ok(()); }
        
        display::section_header(&format!("HISTORICAL URL DISCOVERY: {}", target));
        
        match neutron_url::discover_urls(&target, true, false).await {
            Ok(urls) => {
                display::success(&format!("Found {} historical URLs", urls.len()));
                for url in urls.iter().take(30) {
                    println!("  • {} (from: {})", url.url, url.source);
                }
                if urls.len() > 30 {
                    display::info(&format!("... and {} more URLs", urls.len() - 30));
                }
            }
            Err(e) => display::error(&format!("Discovery failed: {}", e)),
        }
        Ok(())
    }
    
    async fn run_web_crawler(&self) -> anyhow::Result<()> {
        let target = self.get_input("Enter target URL");
        if target.is_empty() { return Ok(()); }
        
        display::section_header(&format!("WEB CRAWLING: {}", target));
        display::warning("Crawler not yet fully implemented. Use katana CLI directly for now.");
        Ok(())
    }
    
    async fn run_js_endpoint_extraction(&self) -> anyhow::Result<()> {
        let target = self.get_input("Enter target URL or domain");
        if target.is_empty() { return Ok(()); }
        
        display::section_header(&format!("JAVASCRIPT ENDPOINT EXTRACTION: {}", target));
        
        let urls = if target.starts_with("http") {
            vec![target.clone()]
        } else {
            vec![format!("https://{}", target)]
        };
        
        match neutron_js::analyze_javascript(&urls).await {
            Ok((endpoints, _)) => {
                display::success(&format!("Found {} endpoints", endpoints.len()));
                for ep in endpoints.iter().take(30) {
                    println!("  • {}", ep.endpoint);
                }
                if endpoints.len() > 30 {
                    display::info(&format!("... and {} more endpoints", endpoints.len() - 30));
                }
            }
            Err(e) => display::error(&format!("Extraction failed: {}", e)),
        }
        Ok(())
    }
    
    async fn run_secret_scanning(&self) -> anyhow::Result<()> {
        let target = self.get_input("Enter target URL or domain");
        if target.is_empty() { return Ok(()); }
        
        display::section_header(&format!("SECRET SCANNING: {}", target));
        
        let urls = if target.starts_with("http") {
            vec![target.clone()]
        } else {
            vec![format!("https://{}", target)]
        };
        
        match neutron_js::analyze_javascript(&urls).await {
            Ok((_, secrets)) => {
                if secrets.is_empty() {
                    display::info("No secrets found");
                } else {
                    display::warning(&format!("Found {} potential secrets!", secrets.len()));
                    for secret in secrets.iter().take(20) {
                        let confidence_pct = (secret.confidence * 100.0) as u32;
                        println!("  [{}%] {} - {} chars", confidence_pct, secret.secret_type, secret.value.len());
                    }
                    if secrets.len() > 20 {
                        display::info(&format!("... and {} more secrets", secrets.len() - 20));
                    }
                }
            }
            Err(e) => display::error(&format!("Scanning failed: {}", e)),
        }
        Ok(())
    }
    
    async fn run_dns_scan(&self) -> anyhow::Result<()> {
        let target = self.get_input("Enter domain");
        if target.is_empty() { return Ok(()); }
        
        display::section_header(&format!("DNS RECORDS: {}", target));
        
        match neutron_dns::enumerate_dns_records(&target).await {
            Ok(records) => {
                if records.is_empty() {
                    display::info("No DNS records found");
                } else {
                    println!("\n  DNS Records for: {}", target);
                    for record in &records {
                        println!("  {} → {}", record.record_type, record.value);
                    }
                    display::success(&format!("{} DNS records found", records.len()));
                }
            }
            Err(e) => display::error(&format!("DNS scan failed: {}", e)),
        }
        Ok(())
    }
    
    async fn run_tech_scan(&self) -> anyhow::Result<()> {
        self.run_tech_fingerprint().await
    }
    
    async fn run_tech_fingerprint(&self) -> anyhow::Result<()> {
        let target = self.get_input("Enter target URL");
        if target.is_empty() { return Ok(()); }
        
        display::section_header(&format!("TECHNOLOGY FINGERPRINTING: {}", target));
        
        match neutron_tech::identify_technologies(&target).await {
            Ok(techs) => {
                display::success(&format!("Found {} technologies", techs.len()));
                for tech in techs {
                    println!("  • {} {} ({})", 
                        tech.name, 
                        tech.version.unwrap_or_default(),
                        tech.category
                    );
                }
            }
            Err(e) => display::error(&format!("Fingerprinting failed: {}", e)),
        }
        Ok(())
    }
    
    async fn run_network_intel(&self) -> anyhow::Result<()> {
        let target = self.get_input("Enter domain");
        if target.is_empty() { return Ok(()); }
        
        display::section_header(&format!("NETWORK INTELLIGENCE: {}", target));
        
        match neutron_network::gather_network_intel(&target).await {
            Ok(intel) => {
                println!("\n  Domain: {}", intel.domain);
                if !intel.asn_numbers.is_empty() {
                    println!("  ASN: {}", intel.asn_numbers.join(", "));
                }
                if !intel.ip_ranges.is_empty() {
                    println!("  IP Ranges: {}", intel.ip_ranges.join(", "));
                }
                if !intel.reverse_dns.is_empty() {
                    println!("  Reverse DNS: {}", intel.reverse_dns.join(", "));
                }
                display::success("Network intel gathered");
            }
            Err(e) => display::error(&format!("Intel gathering failed: {}", e)),
        }
        Ok(())
    }
    
    async fn run_username_osint(&self) -> anyhow::Result<()> {
        let username = self.get_input("Enter username to search");
        if username.is_empty() { return Ok(()); }
        
        display::section_header(&format!("USERNAME OSINT: {}", username));
        
        let engine = neutron_user::UserSearchEngine::new()?;
        match engine.search_username(&username).await {
            Ok(results) => {
                display::success(&format!("Found {} profiles", results.len()));
                for profile in results.iter().take(30) {
                    println!("  • [{}] {}", profile.platform, profile.url);
                }
                if results.len() > 30 {
                    display::info(&format!("... and {} more profiles", results.len() - 30));
                }
            }
            Err(e) => display::error(&format!("Search failed: {}", e)),
        }
        Ok(())
    }
    
    async fn run_ip_intelligence(&self) -> anyhow::Result<()> {
        let ip = self.get_input("Enter IP address");
        if ip.is_empty() { return Ok(()); }
        
        display::section_header(&format!("IP INTELLIGENCE: {}", ip));
        
        match neutron_ip::analyze_ip(&ip).await {
            Ok(intel) => {
                if let Some(geo) = &intel.geolocation {
                    println!("\n  Location:");
                    println!("    Country: {}", geo.country);
                    println!("    City: {}", geo.city);
                    println!("    ISP: {}", geo.isp);
                    println!("    Coordinates: {}, {}", geo.lat, geo.lon);
                }
                display::success("IP analysis complete");
            }
            Err(e) => display::error(&format!("IP analysis failed: {}", e)),
        }
        Ok(())
    }
    
    async fn run_ai_scan(&self) -> anyhow::Result<()> {
        let target = self.get_input("Enter target domain/URL");
        if target.is_empty() { return Ok(()); }
        
        display::section_header(&format!("AI-POWERED VULNERABILITY SCAN: {}", target));
        
        match neutron_ai::AiScanner::new() {
            Ok(scanner) => {
                scanner.interactive_scan(&target).await?;
            }
            Err(e) => display::error(&format!("AI scanner initialization failed: {}", e)),
        }
        Ok(())
    }
    
    fn setup_tools(&self) -> anyhow::Result<()> {
        display::section_header("PROJECTDISCOVERY TOOL SETUP");
        neutron_integrations::installer::Installer::check_and_install_all()?;
        display::success("Tool setup complete!");
        Ok(())
    }
    
    fn show_cheat_sheet(&self) -> anyhow::Result<()> {
        display::section_header("NEUTRON-NG CHEAT SHEET");
        display::info("Cheat sheet functionality coming soon!");
        display::info("For now, use --help or visit the README");
        Ok(())
    }
    
    async fn run_quick_scan(&self) -> anyhow::Result<()> {
        let target = self.get_target_input()?;
        
        display::module_header(&format!("Quick Scan: {}", target));
        
        // Step 1: Subdomain discovery
        display::info("Step 1/2: Discovering subdomains...");
        match neutron_subdomain::enumerate_subdomains(&target, true, false).await {
            Ok(results) => {
                display::success(&format!("✓ Found {} subdomains", results.len()));
            }
            Err(e) => display::warning(&format!("Subdomain scan issue: {}", e)),
        }
        
        // Step 2: URL discovery
        display::info("Step 2/2: Collecting URLs...");
        match neutron_url::discover_urls(&target, true, false).await {
            Ok(results) => {
                display::success(&format!("✓ Found {} URLs", results.len()));
            }
            Err(e) => display::warning(&format!("URL discovery issue: {}", e)),
        }
        
        display::info("Quick scan complete! 🎯");
        Ok(())
    }
    
    async fn run_infrastructure_scan(&self) -> anyhow::Result<()> {
        let target = self.get_target_input()?;
        
        display::section_header("INFRASTRUCTURE ANALYSIS");
        
        // DNS
        display::info("Analyzing DNS records...");
        match neutron_dns::enumerate_dns_records(&target).await {
            Ok(records) => {
                if !records.is_empty() {
                    display::success(&format!("✓ Found {} DNS records", records.len()));
                }
            }
            Err(e) => display::warning(&format!("DNS analysis: {}", e)),
        }
        
        // Technology  
        display::info("Identifying technologies...");
        let url = format!("https://{}", target);
        match neutron_tech::detect_technologies(&url).await {
            Ok(tech) => {
                let technologies: Vec<_> = tech;
                if !technologies.is_empty() {
                    display::success(&format!("✓ Detected {} technologies", technologies.len()));
                }
            }
            Err(e) => display::warning(&format!("Tech detection: {}", e)),
        }
        
        display::success("Infrastructure scan complete!");
        Ok(())
    }
    
    async fn run_vulnerability_scan(&self) -> anyhow::Result<()> {
        display::section_header("VULNERABILITY SCANNER");
        
        print!("  Scan directory (or press Enter for latest): ");
        std::io::stdout().flush()?;
        
        let mut scan_dir_input = String::new();
        std::io::stdin().read_line(&mut scan_dir_input)?;
        
        if scan_dir_input.trim().is_empty() {
            display::info("This feature scans URLs from previous reconnaissance");
            display::info("Run a scan first: Option 1 (Quick Scan) or 2 (Full Scan)");
            return Ok(());
        }
        
        display::info("Deep vulnerability scanner ready!");
        display::info("Feature: XSS and SQLi detection with async crawling");
        
        Ok(())
    }
}
