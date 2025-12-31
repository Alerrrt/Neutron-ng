use anyhow::Result;
use neutron_types::{OutputFormat, ScanResult};
use std::path::Path;

pub mod json;
pub mod console;

/// Trait for output handlers
pub trait OutputHandler {
    fn write(&self, results: &[ScanResult], output_path: &Path) -> Result<()>;
}

/// Write results in the specified format
pub fn write_results(
    results: &[ScanResult],
    output_path: &Path,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            json::JsonOutputHandler.write(results, output_path)
        }
        OutputFormat::Console => {
            console::ConsoleOutputHandler.write(results, output_path)
        }
        _ => {
            tracing::warn!("Output format {:?} not yet implemented", format);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_formats() {
        // Basic test to ensure output module compiles
        assert!(true);
    }
}
