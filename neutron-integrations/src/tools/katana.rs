use anyhow::Result;
use crate::ToolWrapper;
use tracing::info;

pub struct Katana(ToolWrapper);

impl Katana {
    pub fn new() -> Result<Self> {
        Ok(Self(ToolWrapper::new("katana")?))
    }

    pub async fn run(&self, urls: &[String]) -> Result<Vec<String>> {
        info!("Running Katana on {} URLs", urls.len());
        let input = urls.join("\n");
        let args = ["-silent", "-d", "3", "-jc"];
        let output = self.0.run(&args, Some(&input)).await?;
        
        Ok(output.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }
}
