use std::io::{self, Write};

/// Display the Neutron-ng ASCII art banner
pub fn display_banner() {
    println!(r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ███╗   ██╗███████╗██╗   ██╗████████╗██████╗  ██████╗ ███╗   ██╗           ║
║   ████╗  ██║██╔════╝██║   ██║╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║           ║
║   ██╔██╗ ██║█████╗  ██║   ██║   ██║   ██████╔╝██║   ██║██╔██╗ ██║           ║
║   ██║╚██╗██║██╔══╝  ██║   ██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║           ║
║   ██║ ╚████║███████╗╚██████╔╝   ██║   ██║  ██║╚██████╔╝██║ ╚████║           ║
║   ╚═╝  ╚═══╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝           ║
║                                                                               ║
║              Advanced Reconnaissance Engine v{}                         ║
║              Comprehensive Security Intelligence Tool                        ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#, env!("CARGO_PKG_VERSION"));
}

/// Display a section header
pub fn section_header(title: &str) {
    println!("\n╔═══════════════════════════════════════════════════════════════════════════════╗");
    println!("║ {:<77} ║", title);
    println!("╚═══════════════════════════════════════════════════════════════════════════════╝");
}

/// Display a status line
pub fn status(label: &str, value: &str) {
    println!("  [*] {}: {}", label, value);
}

/// Display a success message
pub fn success(message: &str) {
    println!("  [+] {}", message);
}

/// Display a warning message
pub fn warning(message: &str) {
    println!("  [!] {}", message);
}

/// Display an error message
pub fn error(message: &str) {
    println!("  [-] {}", message);
}

/// Display an info message
pub fn info(message: &str) {
    println!("  [i] {}", message);
}

/// Prompt user for input
pub fn prompt(message: &str) -> String {
    print!("  [?] {}: ", message);
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

/// Prompt for API key with optional skip
pub fn prompt_api_key(service: &str, env_var: &str) -> Option<String> {
    // Check if already set in environment
    if let Ok(key) = std::env::var(env_var) {
        if !key.is_empty() {
            status(&format!("{} API Key", service), "Found in environment");
            return Some(key);
        }
    }
    
    println!();
    info(&format!("{} API key not found in environment", service));
    info(&format!("Environment variable: {}", env_var));
    
    let input = prompt(&format!("Enter {} API key (or press Enter to skip)", service));
    
    if input.is_empty() {
        warning(&format!("Skipping {} - limited results may be available", service));
        None
    } else {
        // Set in environment for this session
        std::env::set_var(env_var, &input);
        success(&format!("{} API key configured", service));
        Some(input)
    }
}

/// Display a progress indicator
pub fn progress(phase: &str, current: usize, total: usize) {
    println!("  [*] {}: {}/{}", phase, current, total);
}

/// Display results summary
pub fn results_summary(subdomains: usize, urls: usize, endpoints: usize, secrets: usize) {
    println!("\n╔═══════════════════════════════════════════════════════════════════════════════╗");
    println!("║ SCAN RESULTS SUMMARY                                                          ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Subdomains Found:      {:<54} ║", subdomains);
    println!("║  URLs Discovered:       {:<54} ║", urls);
    println!("║  JS Endpoints:          {:<54} ║", endpoints);
    println!("║  Potential Secrets:     {:<54} ║", secrets);
    println!("╚═══════════════════════════════════════════════════════════════════════════════╝");
}

/// Display module header
pub fn module_header(module: &str) {
    println!("\n┌───────────────────────────────────────────────────────────────────────────────┐");
    println!("│ MODULE: {:<70} │", module.to_uppercase());
    println!("└───────────────────────────────────────────────────────────────────────────────┘");
}

/// Display a simple table
pub fn table_row(col1: &str, col2: &str, col3: &str) {
    println!("  │ {:<30} │ {:<25} │ {:<15} │", col1, col2, col3);
}

/// Display table header
pub fn table_header(col1: &str, col2: &str, col3: &str) {
    println!("  ┌{:─<32}┬{:─<27}┬{:─<17}┐", "", "", "");
    println!("  │ {:<30} │ {:<25} │ {:<15} │", col1, col2, col3);
    println!("  ├{:─<32}┼{:─<27}┼{:─<17}┤", "", "", "");
}

/// Display table footer
pub fn table_footer() {
    println!("  └{:─<32}┴{:─<27}┴{:─<17}┘", "", "", "");
}
