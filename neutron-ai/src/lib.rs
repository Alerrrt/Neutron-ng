use anyhow::{Result, Context};
use neutron_integrations::ToolWrapper;
use tracing::{info, warn};
use colored::*;
use inquire::Select;

pub mod prompts;

pub struct AiScanner {
    nuclei: ToolWrapper,
}

impl AiScanner {
    pub fn new() -> Result<Self> {
        let nuclei = ToolWrapper::new("nuclei")
            .context("Nuclei is not installed. Run 'neutron-ng setup' first.")?;
        Ok(Self { nuclei })
    }

    /// Interactive mode to select a prompt and run the scan
    pub async fn interactive_scan(&self, target: &str) -> Result<()> {
        println!("{}", "\n🤖 NEUTRON AI: Intelligent Vulnerability Scanning".cyan().bold());
        println!("{}", "Select a scan objective from the curated library:".dimmed());

        let options: Vec<String> = prompts::PROMPTS.iter()
            .map(|(title, desc)| format!("{} - {}", title.bold(), desc.dimmed()))
            .collect();

        let selection = Select::new("Choose scan objective:", options).prompt()?;
        
        // Find the matching prompt description
        let selected_prompt = prompts::PROMPTS.iter()
            .find(|(title, desc)| selection.contains(title))
            .map(|(_, desc)| *desc)
            .unwrap_or("Find critical vulnerabilities");

        self.run_ai_scan(target, selected_prompt).await
    }

    /// Run non-interactive AI scan with a custom or selected prompt
    pub async fn run_ai_scan(&self, target: &str, prompt: &str) -> Result<()> {
        info!("Starting AI Scan on {} with prompt: '{}'", target, prompt);
        
        // nuclei -u target.com -ai "prompt"
        // Note: -ai usually requires an OpenAI key set in Nuclei config (`nuclei-config.yaml`)
        // Neutron assumes the user has configured this if they want to use AI.
        // We will add a check/warning about the API key.
        
        let args = ["-u", target, "-ai", prompt];
        
        // We stream output to let user see Nuclei's progress directly
        // The generic runner captures output, which might hide the AI thinking process.
        // For AI, we might want to let it inherit stdout/stderr for real-time feedback.
        // Let's modify usage or accept that ToolWrapper captures it. 
        // For now, let's use the wrapper but maybe log that it might take time.
        
        println!("{}", "⚠️  Note: Ensure OpenAI API key is configured in Nuclei ($HOME/.config/nuclei/config.yaml)".yellow());
        
        match self.nuclei.run(&args, None).await {
            Ok(output) => {
                println!("\n{}", output);
                Ok(())
            }
            Err(e) => {
                // Nuclei -ai might fail if no key.
                warn!("Nuclei AI scan failed. Error: {}", e);
                // Try to provide helpful hint
                if e.to_string().contains("key") {
                    println!("{}", "❌ Missing OpenAI API key in Nuclei config.".red());
                }
                Err(e)
            }
        }
    }
}
