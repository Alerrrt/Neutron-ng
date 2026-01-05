use neutron_core::ResultStorage;
use neutron_integrations::tools::{Subfinder, Naabu, Httpx, Nuclei};
use crate::cli::display;
use tracing::{info, warn, error};
use anyhow::Result;

pub struct ScanEngine {
    target: String,
    output_dir: String,
    use_pd_tools: bool,
}

impl ScanEngine {
    pub fn new(target: String, output_dir: String, use_pd_tools: bool) -> Self {
        Self {
            target,
            output_dir,
            use_pd_tools,
        }
    }

    pub async fn run(&self) -> Result<()> {
        display::section_header(&format!("SCANNING TARGET: {}", self.target));
        
        let mut storage = ResultStorage::new(&self.target, Some(&self.output_dir))?;
        display::status("Scan ID", storage.scan_id());
        
        // ---------------------------------------------------------
        // PHASE 1: SUBDOMAINS
        // ---------------------------------------------------------
        display::module_header("Phase 1: Subdomain Enumeration");
        let mut all_subdomains = Vec::new();
        
        // Native Neutron Recon
        match neutron_subdomain::enumerate_subdomains(&self.target, true, true).await {
             Ok(results) => {
                 display::success(&format!("Neutron found {} subdomains", results.len()));
                 storage.save_subdomains(&results)?;
                 all_subdomains.extend(results);
             }
             Err(e) => display::error(&format!("Neutron enumeration failed: {}", e)),
        }

        // ProjectDiscovery Subfinder (if enabled)
        if self.use_pd_tools {
            if let Ok(subfinder) = Subfinder::new() {
                 match subfinder.run(&self.target).await {
                     Ok(subs) => {
                         display::success(&format!("Subfinder found {} subdomains", subs.len()));
                         // Merge logically (simple de-dupe happens in storage or final summary)
                         // For now, allow duplicates or handle merging later
                     }
                     Err(e) => display::warning(&format!("Subfinder failed: {}", e)),
                 }
            } else {
                display::warning("Subfinder not installed (skipped)");
            }
        }

        // ---------------------------------------------------------
        // PHASE 2: URL & PORT DISCOVERY
        // ---------------------------------------------------------
        display::module_header("Phase 2: Discovery (URLs & Ports)");
        
        // Native URL
        let mut all_urls = Vec::new();
        if let Ok(urls) = neutron_url::discover_urls(&self.target, true, false).await {
             display::success(&format!("Neutron found {} URLs", urls.len()));
             storage.save_urls(&urls)?;
             all_urls.extend(urls);
        }
        
        // PD Naabu & HTTPX
        if self.use_pd_tools {
            // Naabu
            if let Ok(naabu) = Naabu::new() {
                match naabu.run(&self.target).await {
                    Ok(ports) => display::success(&format!("Naabu found {} open ports", ports.len())),
                    Err(e) => display::warning(&format!("Naabu failed: {}", e)),
                }
            }
            
            // HTTPX (Probing)
            // Collect all subdomains to probe
            let probe_targets: Vec<String> = all_subdomains.iter().map(|s| s.subdomain.clone()).collect();
            if !probe_targets.is_empty() {
                 if let Ok(httpx) = Httpx::new() {
                     match httpx.run(&probe_targets).await {
                         Ok(live_urls) => {
                             display::success(&format!("HTTPX found {} live URLs", live_urls.len()));
                             // We could save these as "live_assets.txt"
                         }
                         Err(e) => display::warning(&format!("HTTPX failed: {}", e)),
                     }
                 }
            }
        }

        // ---------------------------------------------------------
        // PHASE 3: ANALYSIS (JS, VULNS)
        // ---------------------------------------------------------
        display::module_header("Phase 3: Analysis");
        
        // Native JS Analysis
        // ... (Existing logic shifted here)
        
        // PD Nuclei
        if self.use_pd_tools {
             if let Ok(nuclei) = Nuclei::new() {
                 let targets_for_nuclei: Vec<String> = all_urls.iter().map(|u| u.url.clone()).collect();
                 // Limit for demo/performance if needed, or scan all
                 let scan_targets = if targets_for_nuclei.is_empty() {
                     vec![format!("https://{}", self.target)]
                 } else {
                     targets_for_nuclei.into_iter().take(50).collect() // Scan top 50 URLs
                 };
                 
                 match nuclei.run(&scan_targets, &storage.scan_dir().to_string_lossy()).await {
                     Ok(report) => display::success(&format!("Nuclei scan complete. Report: {}", report)),
                     Err(e) => display::warning(&format!("Nuclei failed: {}", e)),
                 }
             }
        }
        
        Ok(())
    }
}
