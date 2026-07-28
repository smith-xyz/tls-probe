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

        #[arg(
            long,
            help = "Target kernel arch (x86_64, aarch64). Defaults to host arch."
        )]
        target_arch: Option<String>,
    },
    Build {
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf {
            profile,
            target_arch,
        } => {
            let arch = target_arch.unwrap_or_else(detect_host_arch);
            build_ebpf(&profile, &arch)
        }
        Commands::Build { release } => build_all(release),
    }
}

fn detect_host_arch() -> String {
    std::env::consts::ARCH.to_string()
}

fn build_ebpf(profile: &str, target_arch: &str) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir("crates/tls-probe-ebpf");
    cmd.args(["+nightly", "build"]);

    if profile == "release" {
        cmd.arg("--release");
    }

    let rustflags = format!("--cfg bpf_target_arch=\"{}\"", target_arch);
    cmd.env("CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS", &rustflags);

    println!("Building eBPF for target arch: {}", target_arch);

    let status = cmd.status().context("Failed to run cargo build for eBPF")?;

    if !status.success() {
        anyhow::bail!("eBPF build failed");
    }

    println!(
        "eBPF program built successfully (target_arch={})",
        target_arch
    );
    Ok(())
}

fn build_all(release: bool) -> Result<()> {
    let arch = detect_host_arch();
    build_ebpf(if release { "release" } else { "dev" }, &arch)?;

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
