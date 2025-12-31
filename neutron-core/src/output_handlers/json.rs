use anyhow::Result;
use neutron_types::ScanResult;
use std::path::Path;
use std::fs;

pub struct JsonOutputHandler;

impl super::OutputHandler for JsonOutputHandler {
    fn write(&self, results: &[ScanResult], output_path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(results)?;
        fs::create_dir_all(output_path.parent().unwrap_or(Path::new(".")))?;
        fs::write(output_path, json)?;
        tracing::info!("Wrote {} results to {:?}", results.len(), output_path);
        Ok(())
    }
}
