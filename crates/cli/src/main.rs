use clap::{Parser, Subcommand};
use serde_json::Value;
use uuid::Uuid;
#[derive(Parser)]
struct Args {
    #[arg(
        long,
        env = "FORGEFLOW_API_URL",
        default_value = "http://127.0.0.1:8787"
    )]
    api: String,
    #[arg(long, env = "FORGEFLOW_OWNER_TOKEN", hide_env_values = true)]
    token: Option<String>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Initialize private Core-only local configuration; never starts execution.
    Init {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        database_url_file: Option<std::path::PathBuf>,
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
    },
    /// Start this installation's Core only. Does not enable autostart.
    Up {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    /// Gracefully stop only the Core recorded for this private configuration.
    Down {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    Status {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    /// Check this installation and PostgreSQL without starting an executor.
    Doctor {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    Executor {
        #[command(subcommand)]
        command: ExecutorCommand,
    },
    Get {
        path: String,
    },
    Command {
        path: String,
        #[arg(long)]
        file: std::path::PathBuf,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Health,
    Projects,
    Events {
        project_id: String,
        #[arg(long, default_value = "0")]
        after: u64,
    },
    Login {
        #[arg(long, env = "FORGEFLOW_OWNER_PASSWORD", hide_env_values = true)]
        password: String,
    },
}
#[derive(Subcommand)]
enum ExecutorCommand {
    Doctor {
        #[arg(long)]
        profile_json: std::path::PathBuf,
        #[arg(long)]
        workspace: std::path::PathBuf,
    },
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let local = match &args.command {
        Command::Init {
            config,
            database_url_file,
            bind,
        } => {
            let mut values = vec![
                "init".to_owned(),
                "--config".into(),
                config.display().to_string(),
                "--bind".into(),
                bind.clone(),
            ];
            if let Some(file) = database_url_file {
                values.extend(["--database-url-file".into(), file.display().to_string()]);
            }
            Some(values)
        }
        Command::Up { config } => Some(vec![
            "up".into(),
            "--config".into(),
            config.display().to_string(),
        ]),
        Command::Down { config } => Some(vec![
            "down".into(),
            "--config".into(),
            config.display().to_string(),
        ]),
        Command::Status { config } => Some(vec![
            "status".into(),
            "--config".into(),
            config.display().to_string(),
        ]),
        Command::Doctor { config } => Some(vec![
            "doctor".into(),
            "--config".into(),
            config.display().to_string(),
        ]),
        _ => None,
    };
    if let Some(values) = local {
        let executable = std::env::current_exe()?;
        let root = executable
            .parent()
            .and_then(|bin| bin.parent())
            .ok_or_else(|| {
                anyhow::anyhow!("installed bin directory is required for Lite commands")
            })?;
        let helper = root.join("ops/lite.py");
        if !helper.is_file() || !root.join("delivery-manifest.json").is_file() {
            anyhow::bail!(
                "Lite commands require an installed directory package containing ops/lite.py and delivery-manifest.json"
            );
        }
        let status = std::process::Command::new("python3")
            .arg(helper)
            .args(values)
            .status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
    if let Command::Executor {
        command:
            ExecutorCommand::Doctor {
                profile_json,
                workspace,
            },
    } = &args.command
    {
        let profile: forgeflow_executors::HeadlessProfile =
            serde_json::from_slice(&std::fs::read(profile_json)?)?;
        let report = forgeflow_executors::doctor(&profile, workspace)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    let client = reqwest::Client::new();
    let (base, path, body, key) = match args.command {
        Command::Init { .. }
        | Command::Up { .. }
        | Command::Down { .. }
        | Command::Status { .. }
        | Command::Doctor { .. } => unreachable!("handled local lifecycle above"),
        Command::Executor { .. } => unreachable!("handled local doctor above"),
        Command::Get { path } => ("/api/v1", path, None, None),
        Command::Command {
            path,
            file,
            idempotency_key,
        } => (
            "/api/v1",
            path,
            Some(serde_json::from_slice::<Value>(&std::fs::read(file)?)?),
            Some(idempotency_key.unwrap_or_else(|| Uuid::new_v4().to_string())),
        ),
        Command::Health => ("", "/healthz".into(), None, None),
        Command::Projects => ("/api/v1", "/projects".into(), None, None),
        Command::Events { project_id, after } => (
            "/api/v1",
            format!("/projects/{project_id}/events?after={after}"),
            None,
            None,
        ),
        Command::Login { password } => (
            "/api/v1",
            "/session".into(),
            Some(serde_json::json!({"password":password})),
            None,
        ),
    };
    if !path.starts_with('/') || path.contains("..") {
        anyhow::bail!("path must be an absolute API resource path");
    }
    let url = format!("{}{}{}", args.api.trim_end_matches('/'), base, path);
    let mut request = if let Some(body) = body {
        client.post(url).json(&body)
    } else {
        client.get(url)
    };
    if let Some(token) = args.token {
        request = request.bearer_auth(token);
    }
    if let Some(key) = key {
        request = request.header("Idempotency-Key", key);
    }
    let mut response = request.send().await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {status}: {}", response.text().await?);
    }
    if response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"))
    {
        use std::io::Write;
        while let Some(chunk) = response.chunk().await? {
            std::io::stdout().write_all(&chunk)?;
            std::io::stdout().flush()?;
        }
    } else {
        let text = response.text().await?;
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            println!("{}", serde_json::to_string_pretty(&value)?)
        } else {
            println!("{text}")
        }
    }
    Ok(())
}
