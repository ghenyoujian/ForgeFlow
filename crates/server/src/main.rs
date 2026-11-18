use clap::Parser;
use forgeflow_api::{AppState, auth::Auth};
use forgeflow_store::Store;
use std::future::IntoFuture;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
mod ecp_dispatcher;
mod restore;
#[derive(Parser)]
struct Args {
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,
    #[arg(long, env = "FORGEFLOW_BIND", default_value = "127.0.0.1:8787")]
    bind: SocketAddr,
    #[arg(long, env = "FORGEFLOW_DATA_ROOT")]
    data_root: PathBuf,
    #[arg(long, env = "FORGEFLOW_CONSOLE_DIR", default_value = "console/dist")]
    console_dir: PathBuf,
    #[arg(long, env = "FORGEFLOW_OWNER_TOKEN", hide_env_values = true)]
    owner_token: Option<String>,
    #[arg(
        long,
        env = "FORGEFLOW_WORKER_TOKEN",
        hide_env_values = true,
        required_unless_present = "restore_relocation_manifest"
    )]
    worker_token: Option<String>,
    #[arg(long, env = "FORGEFLOW_OWNER_PASSWORD", hide_env_values = true)]
    owner_password: Option<String>,
    /// Offline reviewed relocation; exits before auth, dispatch or HTTP startup.
    #[arg(long)]
    restore_relocation_manifest: Option<PathBuf>,
    /// Serve only Owner custody inspection/recovery, without managing authors.
    #[arg(long, conflicts_with = "restore_relocation_manifest")]
    physical_recovery_only: bool,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.restore_relocation_manifest.is_some() {
        // Maintenance stdout is reserved for the public command receipt.
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    }
    if args.restore_relocation_manifest.is_none()
        && !args.bind.ip().is_loopback()
        && std::env::var("FORGEFLOW_ALLOW_REMOTE").as_deref() != Ok("1")
    {
        anyhow::bail!(
            "remote binding requires FORGEFLOW_ALLOW_REMOTE=1 and protected TLS reverse proxy"
        );
    }
    if args.physical_recovery_only {
        return physical_recovery_server(args).await;
    }
    for directory in [
        "artifacts",
        "logs",
        "worktrees",
        "executor-homes",
        "backups",
        "exports",
    ] {
        std::fs::create_dir_all(args.data_root.join(directory))?;
    }
    let _instance_lock = instance_lock(&args.data_root)?;
    let store = Store::connect(&args.database_url).await?;
    // The filesystem lock covers one directory; this independent session lock
    // covers this entire PostgreSQL database, including other data roots.
    let mut authority = store.acquire_core_authority().await?;
    tracing::info!(
        backend_pid = authority.backend_pid(),
        "exclusive PostgreSQL Core authority acquired"
    );
    let (stop_monitor, mut monitor_stop) = tokio::sync::oneshot::channel::<()>();
    let monitor = tokio::spawn(async move {
        // Unexpected task cancellation/panic must not silently release ownership
        // while another runtime thread continues serving or reconciling.
        struct FailStopOnUnexpectedDrop(bool);
        impl Drop for FailStopOnUnexpectedDrop {
            fn drop(&mut self) {
                if self.0 {
                    std::process::exit(75);
                }
            }
        }
        let mut fail_stop = FailStopOnUnexpectedDrop(true);
        tokio::select! { biased;
            error=authority.wait_for_loss()=>{
                tracing::error!(%error, "PostgreSQL Core authority lost; immediate fail-stop without database shutdown writes");
                drop(authority);
                std::process::exit(75);
            },
            stopped=&mut monitor_stop=>{
                if stopped.is_err() {
                    drop(authority);
                    std::process::exit(75);
                }
                let result = authority.close().await;
                fail_stop.0 = false;
                result
            }
        }
    });
    // The monitor is already active during migrations and startup recovery.
    let result = run_owned_core(args, store.clone()).await;
    // No Core pool may remain active after the ownership session is released.
    // Pool close disallows fresh acquisitions and waits for borrowed queries.
    let close_pools = async {
        tokio::join!(
            store.pool().close(),
            store.control_pool().close(),
            store.dispatch_pool().close()
        );
    };
    if tokio::time::timeout(std::time::Duration::from_secs(5), close_pools)
        .await
        .is_err()
    {
        tracing::error!(
            "Core pools did not settle while ownership was held; fail-stop preserves recovery authority"
        );
        std::process::exit(75);
    }
    if stop_monitor.send(()).is_err() {
        tracing::error!("Core authority monitor stopped unexpectedly");
        std::process::exit(75);
    }
    let monitor_result = monitor
        .await
        .map_err(|error| anyhow::anyhow!("Core authority monitor failed: {error}"))?;
    result?;
    monitor_result?;
    Ok(())
}

async fn run_owned_core(args: Args, store: Store) -> anyhow::Result<()> {
    tracing::info!("startup phase=migrate begin");
    store.migrate().await?;
    tracing::info!("startup phase=migrate complete");
    if let Some(manifest) = &args.restore_relocation_manifest {
        let receipt = restore::relocate(&store, manifest, &args.data_root).await?;
        use std::io::Write;
        let mut output = std::io::stdout().lock();
        serde_json::to_writer(&mut output, &receipt)?;
        writeln!(output)?;
        return Ok(());
    }
    let retention_seconds =
        bounded_seconds_env("FORGEFLOW_EVENT_RETENTION_SECONDS", 30 * 24 * 60 * 60)?;
    let archive_interval_seconds =
        bounded_seconds_env("FORGEFLOW_EVENT_ARCHIVE_INTERVAL_SECONDS", 3600)?;
    tracing::info!("startup phase=reconcile begin");
    reconcile_operations(&store).await?;
    tracing::info!("startup phase=reconcile complete");
    if std::env::var("FORGEFLOW_RESTORE_MODE").as_deref() == Ok("1") {
        store.restore_reconcile().await?;
    }
    tracing::info!("startup phase=auth_open begin");
    let auth = Auth::open(
        args.data_root.join("auth.json"),
        args.owner_token,
        args.worker_token.ok_or_else(|| {
            anyhow::anyhow!("worker service token is required outside offline restoration")
        })?,
        args.owner_password,
    )
    .map_err(anyhow::Error::msg)?;
    tracing::info!("startup phase=auth_open complete");
    struct StopBackgroundOnDrop(Auth);
    impl Drop for StopBackgroundOnDrop {
        fn drop(&mut self) {
            self.0.begin_shutdown();
        }
    }
    let _stop_background = StopBackgroundOnDrop(auth.clone());
    let mut background = tokio::task::JoinSet::new();
    let (gateway, gateway_router, native_gateway) = load_gateway(&store, &args.data_root)?;
    let archive_store = store.clone();
    let mut archive_shutdown = auth.shutdown_receiver();
    background.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(archive_interval_seconds));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! { biased; _=archive_shutdown.changed()=>break, _=interval.tick()=>{} }
            if *archive_shutdown.borrow() { break; }
            match archive_store.archive_event_batch(retention_seconds, 1000).await {
                Ok(receipt) if receipt.archived_count > 0 => tracing::info!(
                    archived_count=receipt.archived_count, retention_seconds,
                    "event hot-window classification advanced; full history retained"),
                Ok(_) => {},
                Err(error) => tracing::error!(%error, "event archive classification failed; original history retained"),
            }
        }
    });
    let scheduler_store = store.clone();
    let mut scheduler_shutdown = auth.shutdown_receiver();
    background.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {_=interval.tick()=>{},_=scheduler_shutdown.changed()=>break}
            if let Err(error) = forgeflow_scheduler::pump_once(&scheduler_store).await {
                tracing::error!(%error,"scheduler pump failed");
            }
        }
    });
    let recovery_store = store.clone();
    let mut recovery_shutdown = auth.shutdown_receiver();
    background.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {_=interval.tick()=>{},_=recovery_shutdown.changed()=>break}
            if let Err(error) = recovery_store.expire_leases().await {
                tracing::error!(%error,"lease recovery scan failed");
            }
        }
    });
    if std::env::var("FORGEFLOW_ECP_DISPATCHER_ENABLED").as_deref() == Ok("1") {
        let dispatcher_config = ecp_dispatcher::EcpDispatcherConfig::from_env()
            .map_err(|error| anyhow::anyhow!("invalid ECP dispatcher configuration: {error}"))?;
        let max_in_flight = dispatcher_config.max_in_flight;
        let dispatcher = ecp_dispatcher::EcpDispatcher::new(store.clone(), dispatcher_config);
        let dispatcher_shutdown = auth.shutdown_receiver();
        background.spawn(async move {
            dispatcher.run_claim_loop(dispatcher_shutdown).await;
        });
        tracing::info!(
            max_in_flight,
            "ECP dispatcher claim loop enabled; external consumer receipts remain required"
        );
    }
    let state = Arc::new(AppState {
        store,
        auth,
        data_root: args.data_root,
        console_dir: args.console_dir,
        gateway,
        native_gateway,
    });
    tracing::info!(address=%args.bind, "startup phase=http_bind begin");
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(address=%args.bind,"control plane listening");
    let shutdown_state = state.clone();
    let mut hard_shutdown = state.auth.shutdown_receiver();
    let mut router = forgeflow_api::router(state);
    if let Some(gateway_router) = gateway_router {
        router = router.merge(gateway_router);
    }
    let server=axum::serve(listener,router).with_graceful_shutdown(async move {shutdown_signal().await;shutdown_state.auth.begin_shutdown();let coordination=coordinate_shutdown(&shutdown_state);if let Err(error)=tokio::time::timeout(std::time::Duration::from_secs(12),coordination).await{
        tracing::error!(%error,"shutdown coordination exceeded deadline; fail-stop keeps Core authority until process exit");
        std::process::exit(75);
    }}).into_future();
    tokio::pin!(server);
    tokio::select! {result=&mut server=>{result?;},_=async{let _=hard_shutdown.changed().await;tokio::time::sleep(std::time::Duration::from_secs(20)).await;}=>{
        tracing::error!("bounded graceful shutdown deadline reached; fail-stop keeps Core authority until process exit");
        // Accepted HTTP or blocking Git work may still exist. Do not return and
        // release the ownership connection before the runtime actually exits.
        std::process::exit(75);
    }}
    background.shutdown().await;
    Ok(())
}

async fn physical_recovery_server(args: Args) -> anyhow::Result<()> {
    // Deliberate narrow exemption from exclusive Core ownership: this is Owner
    // custody inspection plus explicit typed physical-resource recovery writes,
    // NOT a read-only server. It performs no migration, startup reconciliation,
    // dispatch, author launch or model gateway activity.
    if !args.bind.ip().is_loopback() {
        anyhow::bail!("physical recovery maintenance must bind loopback");
    }
    if args.owner_token.is_none() {
        anyhow::bail!("physical recovery requires the existing Owner service credential");
    }
    // Separate auth persistence prevents overwriting the running Core's sessions.
    // This router exposes neither login, scheduling nor model gateway endpoints.
    let auth = Auth::open(
        args.data_root.join("physical-recovery-auth.json"),
        args.owner_token,
        args.worker_token
            .ok_or_else(|| anyhow::anyhow!("Worker service credential required"))?,
        None,
    )
    .map_err(anyhow::Error::msg)?;
    let state = Arc::new(AppState {
        store: Store::connect(&args.database_url).await?,
        auth,
        data_root: args.data_root,
        console_dir: args.console_dir,
        gateway: None,
        native_gateway: None,
    });
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(address=%args.bind, "Owner physical recovery maintenance listening");
    axum::serve(listener, forgeflow_api::physical_recovery_router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn bounded_seconds_env(name: &str, default: u64) -> anyhow::Result<u64> {
    let value = match std::env::var(name) {
        Ok(value) => value.parse::<u64>().ok(),
        Err(std::env::VarError::NotPresent) => Some(default),
        Err(_) => None,
    };
    value
        .filter(|seconds| (1..=315_360_000).contains(seconds))
        .ok_or_else(|| anyhow::anyhow!("{name} must be integer seconds in 1..=315360000"))
}

#[derive(serde::Deserialize)]
struct GatewayConfig {
    route_id: String,
    model: String,
    upstream_messages_url: String,
    upstream_secret_file: PathBuf,
    limits: forgeflow_gateway::GatewayBudgetLimits,
    timeout_seconds: u64,
}
fn load_gateway(
    store: &Store,
    data_root: &std::path::Path,
) -> anyhow::Result<(
    Option<Arc<forgeflow_gateway::PgRequestAuthority>>,
    Option<axum::Router>,
    Option<forgeflow_gateway::GatewayState>,
)> {
    let Some(path) = std::env::var_os("FORGEFLOW_GATEWAY_CONFIG") else {
        return Ok((None, None, None));
    };
    let config: GatewayConfig = serde_json::from_slice(&std::fs::read(path)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&config.upstream_secret_file)?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            anyhow::bail!("gateway secret file must restrict permissions to owner only");
        }
    }
    let secret = std::fs::read_to_string(config.upstream_secret_file)?
        .trim()
        .to_string();
    if secret.is_empty() {
        anyhow::bail!("gateway upstream secret is empty");
    }
    let seed_path = data_root.join("gateway-issuer.secret");
    if !seed_path.exists() {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&seed_path)?;
        let seed = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        file.write_all(seed.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&seed_path)?.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("gateway issuer seed must be owner-only");
        }
    }
    let seed = std::fs::read_to_string(seed_path)?;
    let authority = Arc::new(
        forgeflow_gateway::PgRequestAuthority::new(
            store.pool().clone(),
            config.limits,
            std::collections::BTreeMap::from([(config.route_id.clone(), config.model.clone())]),
        )
        .map_err(anyhow::Error::msg)?
        .with_issuer_seed(seed)
        .map_err(anyhow::Error::msg)?,
    );
    let state = forgeflow_gateway::GatewayState::new(
        authority.clone(),
        config.route_id,
        config.upstream_messages_url,
        secret,
        std::time::Duration::from_secs(config.timeout_seconds),
    )?
    .with_native_model(config.model);
    Ok((
        Some(authority),
        Some(forgeflow_gateway::router(state.clone())),
        Some(state),
    ))
}

fn instance_lock(root: &std::path::Path) -> anyhow::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join("server.lock"))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            anyhow::bail!("another server owns this data root");
        }
    }
    Ok(file)
}
async fn reconcile_operations(store: &Store) -> anyhow::Result<()> {
    for project in store.list_projects().await? {
        for mut operation in store
            .list_documents(&project.project_id, "operations")
            .await?
        {
            if operation.get("kind").and_then(serde_json::Value::as_str)
                == Some("VERIFIER_PROCESS_ROOT")
            {
                if let Some(root) = operation
                    .get("verifier_root")
                    .and_then(serde_json::Value::as_str)
                {
                    let root = std::path::Path::new(root);
                    let physical =
                        match operation
                            .get("physical_grant")
                            .filter(|value| !value.is_null())
                            .cloned()
                            .map(
                                serde_json::from_value::<
                                    forgeflow_evidence::PhysicalVerificationContext,
                                >,
                            )
                            .transpose()
                        {
                            Ok(physical) => physical,
                            Err(_) => {
                                tracing::error!(path=%root.display(),"registered physical verifier grant is invalid; quarantine retained");
                                continue;
                            }
                        };
                    // This runs only after the exclusive data-root instance lock and
                    // before HTTP or scheduler startup. No old sequencer can launch
                    // an unused command after its registered grant is sealed here.
                    match forgeflow_evidence::reconcile_registered_verification_runs(
                        root,
                        physical.as_ref(),
                    )
                    .await
                    {
                        Ok(stops) => {
                            let physical_evidence = if physical.is_some() {
                                match forgeflow_evidence::verification_physical_stop_evidence(root)
                                {
                                    Ok(evidence) => evidence,
                                    Err(_) => {
                                        tracing::error!(path=%root.display(),"physical verifier stop evidence incomplete; quarantine retained");
                                        continue;
                                    }
                                }
                            } else {
                                Vec::new()
                            };
                            tracing::info!(count=stops.len(),path=%root.display(),"old verifier groups reconciled");
                            let canonical = root.canonicalize()?;
                            let hash =
                                forgeflow_evidence::sha256(canonical.to_string_lossy().as_bytes());
                            let op = operation
                                .get("operation_id")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("");
                            let attempt = operation
                                .get("attempt_id")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("");
                            let id = format!("verifier-settled-{op}-{}", &hash[..16]);
                            let registration =
                                physical.as_ref().map(|grant| grant.registration_id.clone());
                            if store
                                .get_document(&project.project_id, "operations", &id)
                                .await
                                .is_err()
                            {
                                store.execute_command(forgeflow_domain::CommandIdentity{actor_id:"recovery-service".into(),idempotency_key:id.clone()},forgeflow_domain::CatalogCommand::PutDocument{project_id:project.project_id.clone(),collection:"operations".into(),id:id.clone(),expected_revision:None,value:serde_json::json!({"kind":"VERIFIER_PROCESS_SETTLED","operation_id":id,"registered_operation_id":op,"attempt_id":attempt,"registration_id":registration,"verifier_root":canonical,"status":if stops.is_empty(){"NEVER_LAUNCHED"}else{"STOPPED"},"never_launched":stops.is_empty(),"stop_evidence":stops,"physical_evidence":physical_evidence,"source":"STARTUP_FINGERPRINT_RECONCILIATION"})}).await?;
                            }
                        }
                        Err(error) => {
                            tracing::error!(%error,path=%root.display(),"verifier group remains quarantined");
                        }
                    }
                }
                continue;
            }
            // Owner-authorized integration recovery retains its immutable command
            // and can resume through exact idempotent replay after restart.
            if operation.get("kind").and_then(serde_json::Value::as_str)
                == Some("INTEGRATION_RECOVERY")
            {
                continue;
            }
            if operation.get("status").and_then(serde_json::Value::as_str) != Some("ACCEPTED") {
                continue;
            }
            let Some(id) = operation
                .get("operation_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let revision = operation
                .get("revision")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1);
            operation["status"] = "RECOVERY_REQUIRED".into();
            operation["remediation"]="Control process restarted; inspect verifier process receipts and reconcile held leases before retry.".into();
            store
                .execute_command(
                    forgeflow_domain::CommandIdentity {
                        actor_id: "recovery-service".into(),
                        idempotency_key: format!("{id}:recovery:{revision}"),
                    },
                    forgeflow_domain::CatalogCommand::PutDocument {
                        project_id: project.project_id.clone(),
                        collection: "operations".into(),
                        id,
                        expected_revision: Some(revision),
                        value: operation,
                    },
                )
                .await?;
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM registration");
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
async fn coordinate_shutdown(state: &std::sync::Arc<forgeflow_api::AppState>) {
    let run = uuid::Uuid::new_v4().to_string();
    match state.store.list_projects().await {
        Ok(projects) => {
            for mut project in projects {
                if !project.paused {
                    let revision = project.revision;
                    project.paused = true;
                    if let Err(error) = state
                        .store
                        .execute_command(
                            forgeflow_domain::CommandIdentity {
                                actor_id: "shutdown-service".into(),
                                idempotency_key: format!("{run}:pause:{}", project.project_id),
                            },
                            forgeflow_domain::CatalogCommand::UpdateProject {
                                project: project.clone(),
                                expected_revision: revision,
                            },
                        )
                        .await
                    {
                        tracing::error!(%error,"could not durably pause dispatch");
                    }
                }
                if let Ok(attempts) = state.store.list_attempts(&project.project_id).await {
                    for attempt in attempts.into_iter().filter(|a| !a.state.is_terminal()) {
                        if let Err(error)=state.store.cancel(forgeflow_domain::CancelRequest{actor_id:"shutdown-service".into(),idempotency_key:format!("{run}:cancel:{}",attempt.attempt_id),project_id:attempt.project_id,attempt_id:attempt.attempt_id,expected_revision:attempt.revision,reason:"control server shutdown: preserve process stop and integration decision evidence".into()}).await{tracing::error!(%error,"shutdown attempt cancellation needs recovery");}
                    }
                }
            }
        }
        Err(error) => tracing::error!(%error,"shutdown database authority unavailable"),
    }
    loop {
        let mut unsettled = false;
        if let Ok(projects) = state.store.list_projects().await {
            for project in projects {
                if let Ok(attempts) = state.store.list_attempts(&project.project_id).await {
                    if attempts.iter().any(|a| !a.state.is_terminal()) {
                        unsettled = true;
                    }
                }
            }
        } else {
            break;
        }
        if !unsettled {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}
