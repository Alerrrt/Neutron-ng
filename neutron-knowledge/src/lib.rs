use rust_embed::RustEmbed;
use anyhow::{Result, anyhow};

#[derive(RustEmbed)]
#[folder = "src/data/"]
struct Assets;

pub struct KnowledgeBase;

impl KnowledgeBase {
    pub fn list_topics() -> Vec<String> {
        Assets::iter()
            .map(|f| f.as_ref().replace(".md", "").to_string())
            .collect()
    }

    pub fn get_content(topic: &str) -> Result<String> {
        let filename = format!("{}.md", topic);
        match Assets::get(&filename) {
            Some(content) => {
                let text = std::str::from_utf8(content.data.as_ref())?;
                Ok(text.to_string())
            }
            None => Err(anyhow!("Topic '{}' not found", topic)),
        }
    }
    
    pub fn search(query: &str) -> Vec<(String, String)> {
        let mut results = Vec::new();
        for file in Assets::iter() {
            if let Some(content) = Assets::get(file.as_ref()) {
                if let Ok(text) = std::str::from_utf8(content.data.as_ref()) {
                    if text.to_lowercase().contains(&query.to_lowercase()) {
                        let topic = file.as_ref().replace(".md", "");
                        // Find matching line context
                        for line in text.lines() {
                            if line.to_lowercase().contains(&query.to_lowercase()) {
                                results.push((topic.clone(), line.trim().to_string()));
                                break; // Just one match per file for summary
                            }
                        }
                    }
                }
            }
        }
        results
    }
}
