use colored::*;

mod cli;
mod engine;
use cli::display;
use cli::dashboard::Dashboard;

#[derive(Parser)]
#[command(name = "neutron-ng")]
#[command(about = "Comprehensive reconnaissance engine for security researchers", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run comprehensive reconnaissance scan
    Scan {
        /// Target domain(s) or URL(s)
        #[arg(short, long, value_delimiter = ',')]
        target: Vec<String>,

        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: String,

        /// Output format(s)
        #[arg(short, long, value_delimiter = ',', default_value = "json")]
        format: Vec<String>,
    },

    /// Subdomain enumeration only
    Subdomains {
        /// Target domain(s)
        #[arg(short, long, value_delimiter = ',')]
        target: Vec<String>,
    },

    /// URL discovery only
    Urls {
        /// Target domain(s)
        #[arg(short, long, value_delimiter = ',')]
        target: Vec<String>,
    },

    /// JavaScript analysis only
    JsAnalyze {
        /// Target URL(s)
        #[arg(short, long, value_delimiter = ',')]
        target: Vec<String>,
    },

    /// Vulnerability scanning only
    VulnScan {
        /// Target URL(s)
        #[arg(short, long, value_delimiter = ',')]
        target: Vec<String>,
    },

    /// Cloud infrastructure scanning
    CloudScan {
        /// Target domain(s) or organization
        #[arg(short, long, value_delimiter = ',')]
        target: Vec<String>,
    },

    /// Start web interface server
    Web {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Bind address
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,
    },

    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Generate reports from scan results
    Report {
        /// Scan ID or results directory
        #[arg(short, long)]
        scan_id: String,

        /// Output format
        #[arg(short, long, default_value = "html")]
        format: String,
    },

    /// Search for username across platforms
    User {
        /// Username to search
        #[arg(short, long)]
        target: String,
    },

    /// IP address intelligence
    Ip {
        /// IP address to analyze
        #[arg(short, long)]
        target: String,
    },

    /// Access security cheat sheets
    Cheat {
        /// Topic to view (e.g. "nmap", "reverse_shells") or "list"
        #[arg(index = 1)]
        topic: Option<String>,

        /// Search for a term across all cheat sheets
        /// Search for a term across all cheat sheets
        #[arg(short, long)]
        search: Option<String>,
    },

    /// Install/Update external dependencies
    #[command(help_heading = "Configuration")]
    Setup,

    /// AI-Driven Vulnerability Scanning
    #[command(help_heading = "Advanced")]
    Ai {
        /// Target to scan
        #[arg(short, long)]
        target: String,

        /// Custom AI prompt (optional, defaults to interactive menu)
        #[arg(short, long)]
        prompt: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    Show,
    
    /// Set configuration value
    Set {
        /// Configuration key
        key: String,
        
        /// Configuration value
        value: String,
    },
    
    /// Validate configuration file
    Validate {
        /// Configuration file path
        path: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Display banner
    display::display_banner();
    info!("Neutron-ng v{} starting...", env!("CARGO_PKG_VERSION"));
    
    // If no command provided, launch interactive dashboard
    if cli.command.is_none() {
        let mut dashboard = Dashboard::new();
        return dashboard.run().await;
    }

    match cli.command.unwrap() {
        Commands::Scan { target, output, format } => {
            info!("Running comprehensive scan on targets: {:?}", target);
            
            // Check and prompt for API keys
            display::section_header("API KEY CONFIGURATION");
            display::prompt_api_key("VirusTotal", "NEUTRON_VIRUSTOTAL_API_KEY");
            display::prompt_api_key("SecurityTrails", "NEUTRON_SECURITYTRAILS_API_KEY");
            display::prompt_api_key("Project Discovery Chaos", "NEUTRON_CHAOS_API_KEY");
            
            for domain in &target {
                // Initialize the new Engine
                // Logic: Default to using PD tools if they are found (implicit "smart" behavior)
                // Can add a flag later
                let engine = crate::engine::ScanEngine::new(
                    domain.clone(),
                    output.clone(),
                    true // Enable PD tools integration by default
                );
                
                if let Err(e) = engine.run().await {
                   display::error(&format!("Scan failed for {}: {}", domain, e));
                }
            }
        }
        Commands::Subdomains { target } => {
            info!("Running subdomain enumeration on: {:?}", target);
            
            for domain in &target {
                display::section_header(&format!("SUBDOMAIN ENUMERATION: {}", domain));
                match neutron_subdomain::enumerate_subdomains(domain, true, true).await {
                    Ok(results) => {
                        display::success(&format!("Found {} subdomains", results.len()));
                        println!();
                        display::table_header("Subdomain", "Resolved IPs", "Source");
                        for result in &results {
                            let ips = if result.resolved_ips.is_empty() {
                                "N/A".to_string()
                            } else {
                                result.resolved_ips.join(", ")
                            };
                            display::table_row(&result.subdomain, &ips, &result.source);
                        }
                        display::table_footer();
                    }
                    Err(e) => {
                        display::error(&format!("Enumeration failed: {}", e));
                    }
                }
            }
        }
        Commands::Urls { target } => {
            info!("Running URL discovery on: {:?}", target);
            
            for domain in &target {
                display::section_header(&format!("URL DISCOVERY: {}", domain));
                match neutron_url::discover_urls(domain, true, false).await {
                    Ok(results) => {
                        display::success(&format!("Found {} URLs", results.len()));
                        println!();
                        for result in results.iter().take(20) {
                            display::info(&format!("{} (source: {})", result.url, result.source));
                        }
                        if results.len() > 20 {
                            display::info(&format!("... and {} more URLs", results.len() - 20));
                        }
                    }
                    Err(e) => {
                        display::error(&format!("URL discovery failed: {}", e));
                    }
                }
            }
        }
        Commands::JsAnalyze { target } => {
            info!("Analyzing JavaScript on: {:?}", target);
            
            for url in &target {
                display::section_header(&format!("JAVASCRIPT ANALYSIS: {}", url));
                
                // For JS analysis, we need URLs to analyze
                let urls = if url.starts_with("http") {
                    vec![url.clone()]
                } else {
                    vec![format!("https://{}", url)]
                };
                
                match neutron_js::analyze_javascript(&urls).await {
                    Ok((endpoints, secrets)) => {
                        display::success("Analysis complete");
                        
                        if !endpoints.is_empty() {
                            println!();
                            display::module_header(&format!("API Endpoints: {}", endpoints.len()));
                            for endpoint in endpoints.iter().take(15) {
                                display::info(&format!("{} (from: {})", endpoint.endpoint, endpoint.source_url));
                            }
                            if endpoints.len() > 15 {
                                display::info(&format!("... and {} more endpoints", endpoints.len() - 15));
                            }
                        } else {
                            display::warning("No endpoints found");
                        }
                        
                        if !secrets.is_empty() {
                            println!();
                            display::module_header(&format!("Potential Secrets: {}", secrets.len()));
                            for secret in secrets.iter().take(10) {
                                let confidence_pct = (secret.confidence * 100.0) as u32;
                                display::info(&format!("[{}%] {} - {} chars (from: {})", 
                                    confidence_pct,
                                    secret.secret_type,
                                    secret.value.len(),
                                    secret.source_url
                                ));
                            }
                            if secrets.len() > 10 {
                                display::info(&format!("... and {} more secrets", secrets.len() - 10));
                            }
                            display::warning("Review secrets manually - may contain false positives");
                        } else {
                            display::info("No secrets found");
                        }
                    }
                    Err(e) => {
                        display::error(&format!("Analysis failed: {}", e));
                    }
                }
            }
        }
        Commands::VulnScan { target } => {
            info!("Scanning for vulnerabilities on: {:?}", target);
            display::section_header("VULNERABILITY SCANNING");
            display::warning("Vulnerability scanning not yet implemented");
        }
        Commands::CloudScan { target } => {
            info!("Scanning cloud infrastructure for: {:?}", target);
            display::section_header("CLOUD SCANNING");
            display::warning("Cloud scanning not yet implemented");
        }
        Commands::Web { port, bind } => {
            info!("Starting web interface on {}:{}", bind, port);
            display::section_header("WEB INTERFACE");
            display::warning("Web interface not yet implemented");
        }
        Commands::Config { action } => {
            display::section_header("CONFIGURATION MANAGEMENT");
            match action {
                ConfigAction::Show => {
                    display::warning("Configuration display not yet implemented");
                }
                ConfigAction::Set { key, value } => {
                    info!("Setting config: {} = {}", key, value);
                    display::warning("Configuration update not yet implemented");
                }
                ConfigAction::Validate { path } => {
                    info!("Validating configuration at: {}", path);
                    display::warning("Configuration validation not yet implemented");
                }
            }
        }
        Commands::Report { scan_id, format } => {
            info!("Generating {} report for scan: {}", format, scan_id);
            display::section_header("REPORT GENERATION");
            display::warning("Report generation not yet implemented");
        }
        Commands::User { target } => {
            handle_user_search(target).await?;
        }
        Commands::Ip { target } => {
            handle_ip_intel(target).await?;
        }
                }
            }
        }
        Commands::Cheat { topic, search } => {
            display::section_header("SECURITY KNOWLEDGE BASE");
            
            if let Some(query) = search {
                info!("Searching cheat sheets for: {}", query);
                let results = neutron_knowledge::KnowledgeBase::search(&query);
                if results.is_empty() {
                    display::warning("No matches found.");
                } else {
                    display::success(&format!("Found {} matches:", results.len()));
                    println!();
                    for (topic, context) in results {
                        println!("  {} -> {}", topic.cyan().bold(), context.dimmed());
                    }
                    println!();
                    display::info("Use 'neutron-ng cheat <topic>' to view full content");
                }
                return Ok(());
            }

            match topic.as_deref() {
                Some("list") | None => {
                    let topics = neutron_knowledge::KnowledgeBase::list_topics();
                    display::info("Available Cheat Sheets:");
                    println!();
                    for topic in topics {
                        println!("  • {}", topic.cyan());
                    }
                    println!();
                    display::info("Usage: neutron-ng cheat <topic>");
                }
                Some(t) => {
                    match neutron_knowledge::KnowledgeBase::get_content(t) {
                        Ok(content) => {
                            println!();
                            // Simple markdown rendering (just printing for now, could use a terminal markdown renderer later)
                            println!("{}", content);
                            println!();
                        }
                        Err(_) => {
                            display::error(&format!("Topic '{}' not found.", t));
                            display::info("Use 'neutron-ng cheat list' to see available topics.");
                        }
                    }
                }
            }
        }
        Commands::Setup => {
            display::section_header("DEPENDENCY SETUP");
            info!("Checking and installing dependencies...");
            
            match neutron_integrations::installer::Installer::check_and_install_all() {
                Ok(_) => display::success("All dependencies checked."),
                Err(e) => display::error(&format!("Setup failed: {}", e)),
            }
        }
        Commands::Ai { target, prompt } => {
            display::section_header("AI-DRIVEN VULNERABILITY SCANNING");
            
            let scanner = match neutron_ai::AiScanner::new() {
                Ok(s) => s,
                Err(e) => {
                    display::error(&format!("{}", e));
                    return Ok(());
                }
            };

            if let Some(p) = prompt {
                scanner.run_ai_scan(&target, &p).await?;
            } else {
                if let Err(e) = scanner.interactive_scan(&target) {
                     display::error(&format!("AI scan failed: {}", e));
                }
            }
        }
    }

    Ok(())
}
