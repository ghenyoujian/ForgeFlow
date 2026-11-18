use anyhow::{Context, Result};
use clap::Parser;
use std::{os::unix::process::CommandExt, path::PathBuf};
#[derive(Parser)]
#[command(about = "Apply mandatory Landlock write fence inside ForgeFlow bwrap namespace")]
struct Args {
    #[arg(long)]
    allow_file: Vec<PathBuf>,
    #[arg(long)]
    allow_dir: Vec<PathBuf>,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}
fn main() -> Result<()> {
    let args = Args::parse();
    forgeflow_runtime::sandbox::restrict_writes(&args.allow_file, &args.allow_dir)?;
    let program = args.command.first().context("sandbox command missing")?;
    let error = std::process::Command::new(program)
        .args(&args.command[1..])
        .exec();
    Err(error.into())
}
