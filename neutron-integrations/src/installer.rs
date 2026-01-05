use anyhow::{Result, Context, anyhow};
use std::process::Command;
use tracing::{info, warn, error};
use which::which;

pub struct Installer;

impl Installer {
    /// Check for all required tools and install if missing
    pub fn check_and_install_all() -> Result<()> {
        let tools = vec![
            ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder", "Subdomain enumeration"),
            ("naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu", "Port scanning"),
            ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx", "HTTP probing"),
            ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei", "Vulnerability scanning"),
            ("katana", "github.com/projectdiscovery/katana/cmd/katana", "Web crawling"),
        ];

        println!("\n[*] Checking ProjectDiscovery tools...");
        let mut missing_tools = Vec::new();
        let mut installed_tools = Vec::new();

        for (name, go_package, description) in &tools {
            if which(name).is_err() {
                warn!("Tool '{}' ({}) not found", name, description);
                missing_tools.push((*name, *go_package, *description));
            } else {
                info!("✓ Tool '{}' is installed", name);
                installed_tools.push(*name);
            }
        }

        if missing_tools.is_empty() {
            println!("[+] All tools are installed!\n");
            return Ok(());
        }

        println!("\n[!] Missing {} tool(s). Attempting automatic installation...", missing_tools.len());
        
        for (name, go_package, description) in missing_tools {
            println!("\n[*] Installing {} ({})...", name, description);
            
            if let Err(e) = Self::install_tool(name, go_package) {
                error!("✗ Failed to install '{}': {}", name, e);
                error!("  → Description: {}", description);
                error!("  → Manual install: https://github.com/projectdiscovery/{}/releases", name);
            } else {
                info!("✓ Successfully installed '{}'", name);
            }
        }
        
        Ok(())
    }

    fn install_tool(name: &str, go_package: &str) -> Result<()> {
        // Method A: Go Install (Preferred)
        if which("go").is_ok() {
            info!("Go is installed. Installing '{}' via go install...", name);
            let status = Command::new("go")
                .args(["install", "-v", &format!("{}@latest", go_package)])
                .status()
                .context("Failed to execute go install")?;
                
            if status.success() {
                return Ok(());
            } else {
                warn!("Go install failed for '{}'. Trying binary download...", name);
            }
        } else {
            warn!("Go not found. Attempting direct binary download for '{}'...", name);
        }

        // Method B: Binary Download Fallback
        Self::download_binary(name)?;
        Ok(())
    }

    fn download_binary(name: &str) -> Result<()> {
        info!("Downloading pre-compiled binary for '{}'...", name);
        
        // Determine OS and architecture
        let os = std::env::consts::OS; // "linux", "macos", "windows"
        let arch = std::env::consts::ARCH; // "x86_64", "aarch64"
        
        // Map to GitHub release naming convention
        let (os_name, ext) = match os {
            "linux" => ("linux", ""),
            "macos" => ("darwin", ""),
            "windows" => ("windows", ".exe"),
            _ => return Err(anyhow!("Unsupported OS: {}", os)),
        };
        
        let arch_name = match arch {
            "x86_64" => "amd64",
            "aarch64" | "arm64" => "arm64",
            _ => return Err(anyhow!("Unsupported architecture: {}", arch)),
        };
        
        // Construct download URL (ProjectDiscovery follows consistent naming)
        let binary_name = format!("{}_{}_{}{}", name, os_name, arch_name, ext);
        let download_url = format!(
            "https://github.com/projectdiscovery/{}/releases/latest/download/{}.zip",
            name, binary_name
        );
        
        info!("Downloading from: {}", download_url);
        
        // Download using curl (available on most systems)
        let output = Command::new("curl")
            .args(["-L", "-o", &format!("/tmp/{}.zip", name), &download_url])
            .output()
            .context("Failed to download binary")?;
            
        if !output.status.success() {
            return Err(anyhow!("Download failed for '{}'. Please install manually from: https://github.com/projectdiscovery/{}/releases", name, name));
        }
        
        // Unzip
        let _ = Command::new("unzip")
            .args(["-o", &format!("/tmp/{}.zip", name), "-d", "/tmp"])
            .output();
        
        // Move to GOPATH/bin or ~/.local/bin
        let install_dir = match std::env::var("GOPATH") {
            Ok(gopath) => format!("{}/bin", gopath),
            Err(_) => {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/usr/local".to_string());
                format!("{}/.local/bin", home)
            }
        };
        
        // Create directory if it doesn't exist
        std::fs::create_dir_all(&install_dir)?;
        
        // Move binary
        let src = format!("/tmp/{}/{}{}", name, name, ext);
        let dest = format!("{}/{}{}", install_dir, name, ext);
        std::fs::rename(&src, &dest)
            .or_else(|_| {
                // Fallback: copy if rename fails (cross-device)
                std::fs::copy(&src, &dest).map(|_| ())
            })
            .context("Failed to install binary")?;
        
        // Make executable (Unix-like systems)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dest)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dest, perms)?;
        }
        
        info!("Successfully installed '{}' to {}", name, dest);
        info!("Note: Add {} to your PATH if not already present", install_dir);
        Ok(())
    }
}
