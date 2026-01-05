use anyhow::{Result, Context, anyhow};
use std::process::Command;
use tracing::{info, warn, error};
use which::which;

pub struct Installer;

impl Installer {
    /// Check for all required tools and install if missing
    pub fn check_and_install_all() -> Result<()> {
        let tools = vec![
            ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
            ("naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu"),
            ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx"),
            ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
            ("katana", "github.com/projectdiscovery/katana/cmd/katana"),
        ];

        for (name, go_package) in tools {
            if which(name).is_err() {
                warn!("Tool '{}' not found. Attempting installation...", name);
                
                if let Err(e) = Self::install_tool(name, go_package) {
                    error!("Failed to install '{}': {}", name, e);
                } else {
                    info!("Successfully installed '{}'", name);
                }
            } else {
                info!("Tool '{}' is installed.", name);
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
                warn!("Go install failed for '{}'. Trying fallback...", name);
            }
        }

        // Method B: Binary Download (Fallback - TODO for Phase 20 extension)
        // For MVP, if Go fails, we just error out or warn user to install manually.
        // Implementing full binary download logic requires checking OS/Arch and parsing GitHub releases,
        // which is complex. For now, we rely on Go.
        
        Err(anyhow!("Could not install '{}'. Please install Go or download the binary manually.", name))
    }
}
