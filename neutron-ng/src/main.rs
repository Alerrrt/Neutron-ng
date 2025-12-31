use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod cli;

#[derive(Parser)]
#[command(name = "neutron-ng")]
#[command(about = "Comprehensive reconnaissance engine for security researchers", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

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
        #[arg(short, long, default_value = "./results")]
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

    info!("Neutron-ng v{} starting...", env!("CARGO_PKG_VERSION"));

    match cli.command {
        Commands::Scan { target, output, format } => {
            info!("Running comprehensive scan on targets: {:?}", target);
            info!("Output directory: {}", output);
            info!("Output formats: {:?}", format);
            
            // For now, just run subdomain enumeration as part of scan
            for domain in &target {
                match neutron_subdomain::enumerate_subdomains(domain, true, true).await {
                    Ok(results) => {
                        println!("✅ Found {} subdomains for {}", results.len(), domain);
                        for result in results.iter().take(10) {
                            println!("  - {} ({:?})", result.subdomain, result.resolved_ips);
                        }
                        if results.len() > 10 {
                            println!("  ... and {} more", results.len() - 10);
                        }
                    }
                    Err(e) => {
                        println!("❌ Error scanning {}: {}", domain, e);
                    }
                }
            }
        }
        Commands::Subdomains { target } => {
            info!("Running subdomain enumeration on: {:?}", target);
            
            for domain in &target {
                println!("\n🔍 Enumerating subdomains for: {}", domain);
                match neutron_subdomain::enumerate_subdomains(domain, true, true).await {
                    Ok(results) => {
                        println!("\n✅ Found {} subdomains:\n", results.len());
                        for result in &results {
                            if result.resolved_ips.is_empty() {
                                println!("  {} (source: {})", result.subdomain, result.source);
                            } else {
                                println!("  {} → {} (source: {})", 
                                    result.subdomain, 
                                    result.resolved_ips.join(", "),
                                    result.source
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!("❌ Error: {}", e);
                    }
                }
            }
        }
        Commands::Urls { target } => {
            info!("Running URL discovery on: {:?}", target);
            
            for domain in &target {
                println!("\n🌐 Discovering URLs for: {}", domain);
                match neutron_url::discover_urls(domain, true, false).await {
                    Ok(results) => {
                        println!("\n✅ Found {} URLs:\n", results.len());
                        for result in results.iter().take(20) {
                            println!("  {} (source: {})", result.url, result.source);
                        }
                        if results.len() > 20 {
                            println!("\n  ... and {} more URLs", results.len() - 20);
                        }
                    }
                    Err(e) => {
                        println!("❌ Error: {}", e);
                    }
                }
            }
        }
        Commands::JsAnalyze { target } => {
            info!("Analyzing JavaScript on: {:?}", target);
            
            for url in &target {
                println!("\n📜 Analyzing JavaScript for: {}", url);
                
                // For JS analysis, we need URLs to analyze
                // If provided with a domain, construct a URL
                let urls = if url.starts_with("http") {
                    vec![url.clone()]
                } else {
                    vec![format!("https://{}", url)]
                };
                
                match neutron_js::analyze_javascript(&urls).await {
                    Ok((endpoints, secrets)) => {
                        println!("\n✅ Analysis complete!");
                        
                        if !endpoints.is_empty() {
                            println!("\n🔗 Found {} API endpoints:\n", endpoints.len());
                            for endpoint in endpoints.iter().take(15) {
                                println!("  {} (from: {})", endpoint.endpoint, endpoint.source_url);
                            }
                            if endpoints.len() > 15 {
                                println!("\n  ... and {} more endpoints", endpoints.len() - 15);
                            }
                        } else {
                            println!("\nNo endpoints found");
                        }
                        
                        if !secrets.is_empty() {
                            println!("\n🔑 Found {} potential secrets:\n", secrets.len());
                            for secret in secrets.iter().take(10) {
                                let confidence_pct = (secret.confidence * 100.0) as u32;
                                println!("  [{}%] {} - {} chars (from: {})", 
                                    confidence_pct,
                                    secret.secret_type,
                                    secret.value.len(),
                                    secret.source_url
                                );
                            }
                            if secrets.len() > 10 {
                                println!("\n  ... and {} more secrets", secrets.len() - 10);
                            }
                            println!("\n⚠️  WARNING: Review secrets manually - may contain false positives");
                        } else {
                            println!("\nNo secrets found");
                        }
                    }
                    Err(e) => {
                        println!("❌ Error: {}", e);
                    }
                }
            }
        }
        Commands::VulnScan { target } => {
            info!("Scanning for vulnerabilities on: {:?}", target);
            println!("🔒 Vulnerability scanning not yet implemented");
        }
        Commands::CloudScan { target } => {
            info!("Scanning cloud infrastructure for: {:?}", target);
            println!("☁️ Cloud scanning not yet implemented");
        }
        Commands::Web { port, bind } => {
            info!("Starting web interface on {}:{}", bind, port);
            println!("🌍 Web interface not yet implemented");
        }
        Commands::Config { action } => {
            match action {
                ConfigAction::Show => {
                    println!("📋 Configuration display not yet implemented");
                }
                ConfigAction::Set { key, value } => {
                    info!("Setting config: {} = {}", key, value);
                    println!("✅ Configuration update not yet implemented");
                }
                ConfigAction::Validate { path } => {
                    info!("Validating configuration at: {}", path);
                    println!("✔️ Configuration validation not yet implemented");
                }
            }
        }
        Commands::Report { scan_id, format } => {
            info!("Generating {} report for scan: {}", format, scan_id);
            println!("📊 Report generation not yet implemented");
        }
    }

    Ok(())
}
