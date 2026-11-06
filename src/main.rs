mod audit;
mod config;
mod controller;
mod csr;
mod health;
mod kube;
mod nodes;
mod security;
mod validate;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let config = config::Config::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        signer_name = %config.signer_name,
        "starting home-cloud-controller-manager"
    );

    if let Err(err) = controller::run(config).await {
        tracing::error!(error = %err, "controller exited with error");
        std::process::exit(1);
    }
}
