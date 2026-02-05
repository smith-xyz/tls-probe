use std::process::Command;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    BuildEbpf {
        #[arg(long, default_value = "release")]
        profile: String,
    },
    Build {
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { profile } => build_ebpf(&profile),
        Commands::Build { release } => build_all(release),
    }
}

fn build_ebpf(profile: &str) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir("crates/tls-probe-ebpf");
    cmd.args(["+nightly", "build"]);

    if profile == "release" {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to run cargo build for eBPF")?;

    if !status.success() {
        anyhow::bail!("eBPF build failed");
    }

    println!("eBPF program built successfully");
    Ok(())
}

fn build_all(release: bool) -> Result<()> {
    build_ebpf(if release { "release" } else { "dev" })?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build");
    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to run cargo build")?;

    if !status.success() {
        anyhow::bail!("Build failed");
    }

    println!("Build completed successfully");
    Ok(())
}
