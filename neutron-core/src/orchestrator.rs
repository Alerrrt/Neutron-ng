use anyhow::Result;
use neutron_types::{ScanConfig, ScanMetadata, ScanResult, ScanStatus};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Orchestrator manages scan execution and coordination
pub struct Orchestrator {
    config: Arc<RwLock<ScanConfig>>,
    metadata: Arc<RwLock<ScanMetadata>>,
    results: Arc<RwLock<Vec<ScanResult>>>,
}

impl Orchestrator {
    /// Create a new orchestrator for a scan
    pub fn new(config: ScanConfig) -> Self {
        let metadata = ScanMetadata {
            id: config.id,
            status: ScanStatus::Pending,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            targets: config.targets.clone(),
            modules: config.modules.clone(),
        };

        Self {
            config: Arc::new(RwLock::new(config)),
            metadata: Arc::new(RwLock::new(metadata)),
            results: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Start the scan
    pub async fn start(&self) -> Result<()> {
        info!("Starting scan {}", self.metadata.read().await.id);

        // Update status
        {
            let mut metadata = self.metadata.write().await;
            metadata.status = ScanStatus::Running;
            metadata.started_at = Some(chrono::Utc::now());
        }

        // Execute modules
        let config = self.config.read().await;
        for module in &config.modules {
            info!("Executing module: {:?}", module);
            // Module execution will be implemented in individual module crates
        }

        // Update status to completed
        {
            let mut metadata = self.metadata.write().await;
            metadata.status = ScanStatus::Completed;
            metadata.completed_at = Some(chrono::Utc::now());
        }

        info!("Scan {} completed", self.metadata.read().await.id);
        Ok(())
    }

    /// Pause the scan
    pub async fn pause(&self) -> Result<()> {
        let mut metadata = self.metadata.write().await;
        metadata.status = ScanStatus::Paused;
        info!("Scan {} paused", metadata.id);
        Ok(())
    }

    /// Resume the scan
    pub async fn resume(&self) -> Result<()> {
        let mut metadata = self.metadata.write().await;
        if metadata.status == ScanStatus::Paused {
            metadata.status = ScanStatus::Running;
            info!("Scan {} resumed", metadata.id);
            Ok(())
        } else {
            warn!("Cannot resume scan {} with status {:?}", metadata.id, metadata.status);
            Err(anyhow::anyhow!("Scan is not paused"))
        }
    }

    /// Get current scan metadata
    pub async fn get_metadata(&self) -> ScanMetadata {
        self.metadata.read().await.clone()
    }

    /// Add a result to the scan
    pub async fn add_result(&self, result: ScanResult) {
        self.results.write().await.push(result);
    }

    /// Get all results
    pub async fn get_results(&self) -> Vec<ScanResult> {
        self.results.read().await.clone()
    }

    /// Get results count
    pub async fn results_count(&self) -> usize {
        self.results.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutron_types::{ModuleType, OutputFormat};

    #[tokio::test]
    async fn test_orchestrator_lifecycle() {
        let config = ScanConfig {
            id: Uuid::new_v4(),
            targets: vec!["example.com".to_string()],
            modules: vec![ModuleType::Subdomain],
            output_dir: "./results".to_string(),
            output_formats: vec![OutputFormat::Json],
            concurrency: 10,
            timeout: 30,
            rate_limit: 100,
        };

        let orchestrator = Orchestrator::new(config);
        
        // Check initial status
        let metadata = orchestrator.get_metadata().await;
        assert_eq!(metadata.status, ScanStatus::Pending);

        // Start scan
        orchestrator.start().await.unwrap();
        
        // Check completed status
        let metadata = orchestrator.get_metadata().await;
        assert_eq!(metadata.status, ScanStatus::Completed);
        assert!(metadata.started_at.is_some());
        assert!(metadata.completed_at.is_some());
    }
}
