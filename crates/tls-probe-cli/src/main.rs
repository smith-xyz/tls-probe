mod commands;

#[cfg(target_os = "linux")]
mod capabilities;
#[cfg(target_os = "linux")]
mod error;
#[cfg(target_os = "linux")]
mod loader;
#[cfg(any(target_os = "linux", test))]
mod tls;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "tls-probe")]
#[command(about = "eBPF-based TLS handshake capture for PQC readiness analysis")]
#[command(version)]
struct Cli {
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Capture(commands::capture::CaptureArgs),
    Listeners(commands::listeners::ListenersArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Capture(args) => commands::capture::run(args).await,
        Commands::Listeners(args) => commands::listeners::run(args),
    }
}
