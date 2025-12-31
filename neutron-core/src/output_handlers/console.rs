use anyhow::Result;
use neutron_types::ScanResult;
use std::path::Path;

pub struct ConsoleOutputHandler;

impl super::OutputHandler for ConsoleOutputHandler {
    fn write(&self, results: &[ScanResult], _output_path: &Path) -> Result<()> {
        println!("\n{:=^80}", " Scan Results ");
        println!("Total results: {}\n", results.len());
        
        for (idx, result) in results.iter().enumerate() {
            println!("Result #{}", idx + 1);
            println!("  Module: {:?}", result.module);
            println!("  Timestamp: {}", result.timestamp);
            println!("  Data: {:?}", result.data);
            println!();
        }
        
        Ok(())
    }
}
