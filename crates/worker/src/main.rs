use clap::Parser;
use std::path::PathBuf;
#[derive(Parser)]
#[command(about = "Authenticated standalone ForgeFlow Linux/WSL worker")]
struct Args {
    #[arg(long, env = "FORGEFLOW_WORKER_CONFIG")]
    config: Option<PathBuf>,
    #[arg(long, env = "FORGEFLOW_WORKER_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Bounded trusted runtime proof in its dedicated delegated user service.
    #[arg(long, conflicts_with_all = ["config", "token"])]
    physical_resource_probe: Option<PathBuf>,
    /// Verify the exact configuration and managed runtime pins without network,
    /// registration, author processes or model calls.
    #[arg(long, conflicts_with_all = ["token", "physical_resource_probe"])]
    check_config: bool,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    if let Some(path) = args.physical_resource_probe {
        return forgeflow_worker::physical_resource_probe(&path).await;
    }
    let config_path = args
        .config
        .ok_or_else(|| anyhow::anyhow!("--config is required for a business Worker"))?;
    if args.check_config {
        let config = forgeflow_worker::load_configuration(&config_path)?;
        let result = forgeflow_worker::check_configuration(&config)?;
        println!("{}", serde_json::to_string(&result)?);
        return Ok(());
    }
    let token = args
        .token
        .ok_or_else(|| anyhow::anyhow!("Worker authentication token is required"))?;
    let config = forgeflow_worker::load_configuration(&config_path)?;
    forgeflow_worker::run(config, token).await
}
