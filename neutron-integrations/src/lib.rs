use anyhow::{Result, Context};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{warn, debug};
use which::which;

pub mod tools;
pub mod installer;

/// Generic wrapper for external tools
pub struct ToolWrapper {
    name: String,
    binary_path: String,
}

impl ToolWrapper {
    pub fn new(name: &str) -> Result<Self> {
        let binary_path = which(name)
            .map(|p| p.to_string_lossy().to_string())
            .context(format!("Tool '{}' not found in PATH", name))?;
            
        Ok(Self {
            name: name.to_string(),
            binary_path,
        })
    }

    pub async fn run(&self, args: &[&str], input: Option<&str>) -> Result<String> {
        debug!("Running {} with args: {:?}", self.name, args);
        
        let mut command = Command::new(&self.binary_path);
        command.args(args);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped()); // Capture stderr to avoid terminal noise
        
        if let Some(stdin_data) = input {
            use tokio::io::AsyncWriteExt;
            command.stdin(Stdio::piped());
            
            let mut child = command.spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(stdin_data.as_bytes()).await?;
            }
            
            let output = child.wait_with_output().await?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("{} stderr: {}", self.name, stderr);
                // Don't return error immediately, some tools warn but still work
                // return Err(anyhow!("{} failed: {}", self.name, stderr));
            }
            
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let output = command.output().await?;
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        }
    }
}
