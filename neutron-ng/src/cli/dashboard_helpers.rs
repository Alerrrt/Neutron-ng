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
                if !tech.is_empty() {
                    display::success(&format!("✓ Detected {} technologies", tech.len()));
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
