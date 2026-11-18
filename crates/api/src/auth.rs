use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Json,
    extract::{MatchedPath, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct Auth {
    owner_token: Option<String>,
    worker_token: String,
    worker_credentials_file: Option<PathBuf>,
    file: PathBuf,
    database: Arc<Mutex<AuthDatabase>>,
    login_throttle: Arc<LoginThrottle>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

const LOGIN_WINDOW: StdDuration = StdDuration::from_secs(60);
const LOGIN_ATTEMPTS_PER_WINDOW: usize = 10;
const MAX_PARALLEL_PASSWORD_CHECKS: usize = 2;

struct LoginThrottle {
    attempts: Mutex<VecDeque<Instant>>,
    hashing: Arc<tokio::sync::Semaphore>,
}
impl Default for LoginThrottle {
    fn default() -> Self {
        Self {
            attempts: Mutex::new(VecDeque::new()),
            hashing: Arc::new(tokio::sync::Semaphore::new(MAX_PARALLEL_PASSWORD_CHECKS)),
        }
    }
}
impl LoginThrottle {
    // A single Owner service has a global limit. Caller-controlled proxy/IP
    // headers cannot create new buckets or an unbounded limiter map.
    fn admit(&self, now: Instant) -> Result<(), LoginError> {
        let mut attempts = self.attempts.lock().map_err(|_| LoginError::Unavailable)?;
        while attempts
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= LOGIN_WINDOW)
        {
            attempts.pop_front();
        }
        if attempts.len() >= LOGIN_ATTEMPTS_PER_WINDOW {
            let remaining = LOGIN_WINDOW.saturating_sub(now.saturating_duration_since(attempts[0]));
            return Err(LoginError::Throttled {
                retry_after_seconds: remaining
                    .as_secs()
                    .saturating_add(u64::from(remaining.subsec_nanos() > 0))
                    .max(1),
            });
        }
        attempts.push_back(now);
        Ok(())
    }
}

#[derive(Debug)]
pub enum LoginError {
    InvalidCredentials,
    Throttled { retry_after_seconds: u64 },
    Unavailable,
}
#[derive(Default, Serialize, Deserialize)]
struct AuthDatabase {
    password_hash: Option<String>,
    sessions: HashMap<String, Session>,
    // Older releases interpret every entry in `sessions` as deployment Owner.
    // Keep personal credentials in a separate field those releases ignore.
    #[serde(default)]
    account_sessions: HashMap<String, Session>,
}
impl AuthDatabase {
    fn session(&self, token: &str) -> Option<&Session> {
        self.account_sessions
            .get(token)
            .or_else(|| self.sessions.get(token))
    }
    fn contains_session(&self, token: &str) -> bool {
        self.session(token).is_some()
    }
}
#[derive(Serialize, Deserialize)]
struct Session {
    expires_at: i64,
    csrf: String,
    #[serde(default)]
    actor: Option<SessionActor>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionActor {
    pub account_id: String,
    pub session_epoch: i64,
    #[serde(default)]
    pub integration_id: Option<String>,
}
impl Session {
    fn principal(&self) -> Principal {
        Principal {
            actor_id: self
                .actor
                .as_ref()
                .map(|a| format!("account:{}", a.account_id))
                .unwrap_or_else(|| "owner".into()),
            worker: false,
            worker_id: None,
            project_id: None,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Principal {
    pub actor_id: String,
    pub worker: bool,
    pub worker_id: Option<String>,
    pub project_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerCredentialFile {
    schema_version: String,
    workers: Vec<WorkerCredential>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerCredential {
    worker_id: String,
    project_id: String,
    token: String,
}
fn read_worker_credentials(
    path: &Path,
    owner: Option<&str>,
    master: &str,
) -> Result<Vec<WorkerCredential>, String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let invalid = || "invalid private Worker credential configuration".to_owned();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| invalid())?;
        let metadata = file.metadata().map_err(|_| invalid())?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() > 1_048_576
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() > 1_048_576 {
            return Err(invalid());
        }
        let grants: WorkerCredentialFile = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if grants.schema_version != "forgeflow.worker-credentials.v1" || grants.workers.is_empty() {
            return Err(invalid());
        }
        let mut workers = std::collections::HashSet::new();
        let mut tokens = std::collections::HashSet::new();
        let valid_id = |id: &str| {
            !id.is_empty()
                && id.len() <= 256
                && !id.chars().any(|c| c.is_whitespace() || c.is_control())
        };
        for grant in &grants.workers {
            if !valid_id(&grant.worker_id)
                || !valid_id(&grant.project_id)
                || !(24..=4096).contains(&grant.token.len())
                || !grant.token.is_ascii()
                || grant
                    .token
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                || !workers.insert(grant.worker_id.clone())
                || !tokens.insert(grant.token.clone())
                || constant_equal(&grant.token, master)
                || owner.is_some_and(|token| constant_equal(&grant.token, token))
            {
                return Err(invalid());
            }
        }
        Ok(grants.workers)
    }
    #[cfg(not(unix))]
    {
        let _ = (owner, master, path);
        Err("private Worker credentials require supported Unix file ownership".into())
    }
}
impl Auth {
    pub fn open(
        file: PathBuf,
        owner_token: Option<String>,
        worker_token: String,
        password: Option<String>,
    ) -> Result<Self, String> {
        if worker_token.len() < 24 || owner_token.as_ref().is_some_and(|v| v.len() < 24) {
            return Err("owner/worker service tokens require at least 24 characters".into());
        }
        if owner_token
            .as_deref()
            .is_some_and(|owner| constant_equal(owner, &worker_token))
        {
            return Err("Owner and Worker service credentials must differ".into());
        }
        let mut database: AuthDatabase = if file.exists() {
            serde_json::from_slice(&std::fs::read(&file).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?
        } else {
            AuthDatabase::default()
        };
        // Upgrade early candidates without allowing their personal sessions to
        // become legacy Owner sessions if the application is later rolled back.
        let personal: Vec<String> = database
            .sessions
            .iter()
            .filter(|(_, s)| s.actor.is_some())
            .map(|(t, _)| t.clone())
            .collect();
        for token in personal {
            let session = database.sessions.remove(&token).expect("selected session");
            if database.account_sessions.insert(token, session).is_some() {
                return Err("conflicting personal sessions".into());
            }
        }
        if database
            .account_sessions
            .values()
            .any(|s| s.actor.is_none())
        {
            return Err("personal session identity missing".into());
        }
        if database.password_hash.is_none() {
            if let Some(password) = password {
                if password.len() < 12 {
                    return Err("owner password requires at least 12 characters".into());
                }
                let salt =
                    SaltString::encode_b64(Uuid::new_v4().as_bytes()).map_err(|e| e.to_string())?;
                database.password_hash = Some(
                    Argon2::default()
                        .hash_password(password.as_bytes(), &salt)
                        .map_err(|e| e.to_string())?
                        .to_string(),
                );
            }
        }
        if database.password_hash.is_none() && owner_token.is_none() {
            return Err(
                "set FORGEFLOW_OWNER_PASSWORD or FORGEFLOW_OWNER_TOKEN for initial setup".into(),
            );
        }
        // Pin the configured location at startup; atomically replaced contents
        // are read for each authentication so grants and revocations are immediate.
        let worker_credentials_file =
            std::env::var_os("FORGEFLOW_WORKER_CREDENTIALS_FILE").map(PathBuf::from);
        let worker_credentials = worker_credentials_file
            .as_deref()
            .map(|path| read_worker_credentials(path, owner_token.as_deref(), &worker_token))
            .transpose()?;
        if worker_credentials.as_ref().is_some_and(|grants| {
            grants
                .iter()
                .any(|grant| database.contains_session(&grant.token))
        }) {
            return Err("Worker credential conflicts with existing Owner session".into());
        }
        let auth = Self {
            owner_token,
            worker_token,
            worker_credentials_file,
            file,
            database: Arc::new(Mutex::new(database)),
            login_throttle: Arc::new(LoginThrottle::default()),
            shutdown: tokio::sync::watch::channel(false).0,
        };
        auth.save()?;
        Ok(auth)
    }
    fn save(&self) -> Result<(), String> {
        let database = self.database.lock().map_err(|_| "auth lock")?;
        let bytes = serde_json::to_vec(&*database).map_err(|e| e.to_string())?;
        if let Some(parent) = self.file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let temp = self
            .file
            .with_extension(format!("{}.tmp", Uuid::new_v4().simple()));
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(temp, &self.file).map_err(|e| e.to_string())?;
        if let Some(parent) = self.file.parent() {
            std::fs::File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    pub fn begin_shutdown(&self) {
        let _ = self.shutdown.send_replace(true);
    }
    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown.borrow()
    }
    pub fn shutdown_receiver(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown.subscribe()
    }
    pub fn worker_scope(
        &self,
        principal: &Principal,
        worker: Option<&str>,
        project: Option<&str>,
    ) -> Result<(), String> {
        if !principal.worker {
            return Ok(());
        }
        if principal
            .worker_id
            .as_deref()
            .is_some_and(|expected| worker.is_some_and(|value| value != expected))
        {
            return Err("Worker identity differs from authenticated service scope".into());
        }
        if principal
            .project_id
            .as_deref()
            .is_some_and(|expected| project.is_some_and(|value| value != expected))
        {
            return Err("project differs from authenticated Worker scope".into());
        }
        Ok(())
    }
    pub fn authenticate(&self, headers: &HeaderMap, mutating: bool) -> Option<Principal> {
        if let Some(token) = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
        {
            if self
                .owner_token
                .as_deref()
                .is_some_and(|v| constant_equal(v, token))
            {
                return Some(Principal {
                    actor_id: "owner-service".into(),
                    worker: false,
                    worker_id: None,
                    project_id: None,
                });
            }
            if let Some(path) = &self.worker_credentials_file {
                // Malformed, missing or insecure configured files fail closed;
                // only the direct Owner token above remains a repair entry point.
                let grants =
                    read_worker_credentials(path, self.owner_token.as_deref(), &self.worker_token)
                        .ok()?;
                let database = self.database.lock().ok()?;
                if grants
                    .iter()
                    .any(|grant| database.contains_session(&grant.token))
                {
                    return None;
                }
                if let Some(grant) = grants
                    .iter()
                    .find(|grant| constant_equal(&grant.token, token))
                {
                    return Some(Principal {
                        actor_id: format!("worker-service:{}", grant.worker_id),
                        worker: true,
                        worker_id: Some(grant.worker_id.clone()),
                        project_id: Some(grant.project_id.clone()),
                    });
                }
                // Explicit credentials never fall back to the old fleet wildcard.
            } else if constant_equal(&self.worker_token, token) {
                return Some(Principal {
                    actor_id: "worker-service".into(),
                    worker: true,
                    worker_id: std::env::var("FORGEFLOW_WORKER_ID").ok(),
                    project_id: std::env::var("FORGEFLOW_WORKER_PROJECT_ID").ok(),
                });
            }
            let database = self.database.lock().ok()?;
            if let Some(session) = database
                .session(token)
                .filter(|s| s.expires_at > Utc::now().timestamp())
            {
                return Some(session.principal());
            }
        }
        let cookies = headers.get("cookie")?.to_str().ok()?;
        let token = cookies
            .split(';')
            .find_map(|item| item.trim().strip_prefix("forgeflow_session="))?;
        let database = self.database.lock().ok()?;
        let session = database.session(token)?;
        if session.expires_at <= Utc::now().timestamp() {
            return None;
        }
        if mutating
            && !headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| constant_equal(v, &session.csrf))
        {
            return None;
        }
        Some(session.principal())
    }
    pub async fn login(&self, password: String) -> Result<(String, String), LoginError> {
        self.login_throttle.admit(Instant::now())?;
        if password.is_empty() || password.len() > 4096 {
            return Err(LoginError::InvalidCredentials);
        }
        let permit = self
            .login_throttle
            .hashing
            .clone()
            .try_acquire_owned()
            .map_err(|_| LoginError::Throttled {
                retry_after_seconds: 1,
            })?;
        let auth = self.clone();
        tokio::task::spawn_blocking(move || {
            // Keep the permit in the blocking task even if the HTTP request is
            // cancelled: a disconnected client cannot bypass the memory bound.
            let _permit = permit;
            auth.login_blocking(&password)
        })
        .await
        .map_err(|_| LoginError::Unavailable)?
    }
    fn login_blocking(&self, password: &str) -> Result<(String, String), LoginError> {
        let hash = self
            .database
            .lock()
            .map_err(|_| LoginError::Unavailable)?
            .password_hash
            .clone()
            .ok_or(LoginError::InvalidCredentials)?;
        // Argon2 must neither run on an async executor thread nor hold the
        // session lock used by ordinary authenticated API requests.
        Argon2::default()
            .verify_password(
                password.as_bytes(),
                &PasswordHash::new(&hash).map_err(|_| LoginError::Unavailable)?,
            )
            .map_err(|_| LoginError::InvalidCredentials)?;
        let mut database = self.database.lock().map_err(|_| LoginError::Unavailable)?;
        database
            .sessions
            .retain(|_, s| s.expires_at > Utc::now().timestamp());
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let csrf = Uuid::new_v4().to_string();
        database.sessions.insert(
            token.clone(),
            Session {
                expires_at: (Utc::now() + Duration::hours(8)).timestamp(),
                csrf: csrf.clone(),
                actor: None,
            },
        );
        drop(database);
        self.save().map_err(|_| LoginError::Unavailable)?;
        Ok((token, csrf))
    }
    pub fn session_actor(&self, headers: &HeaderMap) -> Option<SessionActor> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| {
                headers
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| {
                        s.split(';')
                            .find_map(|s| s.trim().strip_prefix("forgeflow_session="))
                    })
            })?;
        self.database
            .lock()
            .ok()?
            .session(token)
            .filter(|s| s.expires_at > Utc::now().timestamp())?
            .actor
            .clone()
    }
    pub fn session_csrf(&self, headers: &HeaderMap) -> Option<String> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| {
                headers
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| {
                        s.split(';')
                            .find_map(|s| s.trim().strip_prefix("forgeflow_session="))
                    })
            })?;
        self.database
            .lock()
            .ok()?
            .session(token)
            .filter(|s| s.expires_at > Utc::now().timestamp())
            .map(|s| s.csrf.clone())
    }
    pub fn issue_account_session(
        &self,
        actor: SessionActor,
    ) -> Result<(String, String), LoginError> {
        let mut database = self.database.lock().map_err(|_| LoginError::Unavailable)?;
        database
            .sessions
            .retain(|_, s| s.expires_at > Utc::now().timestamp());
        database
            .account_sessions
            .retain(|_, s| s.expires_at > Utc::now().timestamp());
        if database.sessions.len() + database.account_sessions.len() >= 10000 {
            return Err(LoginError::Unavailable);
        }
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let csrf = Uuid::new_v4().to_string();
        database.account_sessions.insert(
            token.clone(),
            Session {
                expires_at: (Utc::now() + Duration::hours(8)).timestamp(),
                csrf: csrf.clone(),
                actor: Some(actor),
            },
        );
        drop(database);
        self.save().map_err(|_| LoginError::Unavailable)?;
        Ok((token, csrf))
    }
    pub async fn hash_account_password(&self, password: String) -> Result<String, LoginError> {
        self.password_work(password, None, true).await
    }
    pub async fn verify_account_password(
        &self,
        password: String,
        hash: Option<String>,
    ) -> Result<(), LoginError> {
        self.password_work(password, hash, false).await.map(|_| ())
    }
    async fn password_work(
        &self,
        password: String,
        hash: Option<String>,
        create: bool,
    ) -> Result<String, LoginError> {
        self.login_throttle.admit(Instant::now())?;
        if password.is_empty() || password.len() > 4096 || (create && password.len() < 12) {
            return Err(LoginError::InvalidCredentials);
        }
        let permit = self
            .login_throttle
            .hashing
            .clone()
            .try_acquire_owned()
            .map_err(|_| LoginError::Throttled {
                retry_after_seconds: 1,
            })?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if create {
                let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes())
                    .map_err(|_| LoginError::Unavailable)?;
                return Argon2::default()
                    .hash_password(password.as_bytes(), &salt)
                    .map(|h| h.to_string())
                    .map_err(|_| LoginError::Unavailable);
            }
            if let Some(hash) = hash {
                Argon2::default()
                    .verify_password(
                        password.as_bytes(),
                        &PasswordHash::new(&hash).map_err(|_| LoginError::Unavailable)?,
                    )
                    .map_err(|_| LoginError::InvalidCredentials)?;
                Ok(String::new())
            } else {
                // Spend the same bounded Argon2 work for an unknown address.
                let salt =
                    SaltString::encode_b64(&[0u8; 16]).map_err(|_| LoginError::Unavailable)?;
                let _ = Argon2::default()
                    .hash_password(password.as_bytes(), &salt)
                    .map_err(|_| LoginError::Unavailable)?;
                Err(LoginError::InvalidCredentials)
            }
        })
        .await
        .map_err(|_| LoginError::Unavailable)?
    }
    pub fn logout(&self, headers: &HeaderMap) -> Result<(), String> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| {
                headers
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| {
                        s.split(';')
                            .find_map(|s| s.trim().strip_prefix("forgeflow_session="))
                    })
            });
        if let Some(token) = token {
            let mut database = self.database.lock().map_err(|_| "auth lock")?;
            database.sessions.remove(token);
            database.account_sessions.remove(token);
        }
        self.save()
    }
}
fn constant_equal(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.as_bytes()
            .iter()
            .zip(b.as_bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn personal_credentials_never_appear_in_the_legacy_owner_session_map() {
        let root = std::env::temp_dir().join(format!("personal-auth-{}", Uuid::new_v4()));
        let file = root.join("auth.json");
        let owner = "owner-token-for-account-partition-test".to_string();
        let worker = "worker-token-for-account-partition-test".to_string();
        let auth = Auth::open(file.clone(), Some(owner.clone()), worker.clone(), None).unwrap();
        let (token, _) = auth
            .issue_account_session(SessionActor {
                account_id: "fixture-user".into(),
                session_epoch: 1,
                integration_id: None,
            })
            .unwrap();
        let legacy: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert!(legacy["sessions"].get(&token).is_none());
        assert!(legacy["account_sessions"].get(&token).is_some());
        // Simulate a file written by the early candidate, then exercise upgrade.
        {
            let mut db = auth.database.lock().unwrap();
            let session = db.account_sessions.remove(&token).unwrap();
            db.sessions.insert(token.clone(), session);
        }
        auth.save().unwrap();
        let upgraded = Auth::open(file.clone(), Some(owner), worker, None).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        assert_eq!(
            upgraded.authenticate(&headers, false).unwrap().actor_id,
            "account:fixture-user"
        );
        let safe: serde_json::Value =
            serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        assert!(safe["sessions"].get(&token).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn login_limit_expires_without_an_unbounded_client_map() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..LOGIN_ATTEMPTS_PER_WINDOW {
            throttle.admit(now).unwrap();
        }
        assert!(matches!(
            throttle.admit(now),
            Err(LoginError::Throttled {
                retry_after_seconds: 60
            })
        ));
        assert!(matches!(
            throttle.admit(now + StdDuration::from_millis(59_500)),
            Err(LoginError::Throttled {
                retry_after_seconds: 1
            })
        ));
        throttle.admit(now + LOGIN_WINDOW).unwrap();
        assert_eq!(throttle.attempts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn login_rejects_parallel_overflow_instead_of_queueing_passwords() {
        let auth = Auth {
            owner_token: None,
            worker_token: "unused-worker-token-for-login-test".into(),
            worker_credentials_file: None,
            file: std::env::temp_dir().join(format!("unused-auth-{}", Uuid::new_v4())),
            database: Arc::new(Mutex::new(AuthDatabase::default())),
            login_throttle: Arc::new(LoginThrottle::default()),
            shutdown: tokio::sync::watch::channel(false).0,
        };
        let permits = auth
            .login_throttle
            .hashing
            .clone()
            .acquire_many_owned(2)
            .await
            .unwrap();
        assert!(matches!(
            auth.login("test-password".into()).await,
            Err(LoginError::Throttled {
                retry_after_seconds: 1
            })
        ));
        drop(permits);
        assert!(matches!(
            auth.login("test-password".into()).await,
            Err(LoginError::InvalidCredentials)
        ));
        assert_eq!(auth.login_throttle.hashing.available_permits(), 2);
        assert!(!auth.file.exists());
    }

    #[tokio::test]
    async fn password_login_persists_a_real_session_and_rejects_mismatch() {
        let root = std::env::temp_dir().join(format!("password-auth-{}", Uuid::new_v4()));
        let password = "local-password-test-only";
        let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes()).unwrap();
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        let auth = Auth {
            owner_token: None,
            worker_token: "unused-worker-token-for-login-test".into(),
            worker_credentials_file: None,
            file: root.join("auth.json"),
            database: Arc::new(Mutex::new(AuthDatabase {
                password_hash: Some(hash),
                sessions: HashMap::new(),
                account_sessions: HashMap::new(),
            })),
            login_throttle: Arc::new(LoginThrottle::default()),
            shutdown: tokio::sync::watch::channel(false).0,
        };
        assert!(matches!(
            auth.login("wrong-password".into()).await,
            Err(LoginError::InvalidCredentials)
        ));
        let (token, csrf) = auth.login(password.into()).await.unwrap();
        let saved: AuthDatabase =
            serde_json::from_slice(&std::fs::read(&auth.file).unwrap()).unwrap();
        assert_eq!(saved.sessions.len(), 1);
        assert_eq!(saved.sessions[&token].csrf, csrf);
        assert_eq!(
            std::fs::metadata(&auth.file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        assert!(!auth.authenticate(&headers, false).unwrap().worker);
        assert_eq!(
            auth.login_throttle.hashing.available_permits(),
            MAX_PARALLEL_PASSWORD_CHECKS
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn worker_grants_reload_and_revoke_without_legacy_fallback() {
        let root = std::env::temp_dir().join(format!("worker-auth-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("credentials.json");
        let owner = "owner-token-for-reload-test-only";
        let master = "master-token-for-reload-test-only";
        let old = "old-worker-token-for-reload-test-only";
        let new = "new-worker-token-for-reload-test-only";
        let auth = Auth {
            owner_token: Some(owner.into()),
            worker_token: master.into(),
            worker_credentials_file: Some(path.clone()),
            file: root.join("auth.json"),
            database: Arc::new(Mutex::new(AuthDatabase::default())),
            login_throttle: Arc::new(LoginThrottle::default()),
            shutdown: tokio::sync::watch::channel(false).0,
        };
        let replace = |rows: serde_json::Value| {
            let temp = root.join("replace.json");
            std::fs::write(
                &temp,
                serde_json::to_vec(&serde_json::json!({
                    "schema_version":"forgeflow.worker-credentials.v1","workers":rows
                }))
                .unwrap(),
            )
            .unwrap();
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::rename(temp, &path).unwrap();
        };
        let principal = |token: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
            auth.authenticate(&headers, true)
        };
        let old_grant = serde_json::json!({"worker_id":"old","project_id":"p","token":old});
        let new_grant = serde_json::json!({"worker_id":"new","project_id":"q","token":new});
        replace(serde_json::json!([old_grant]));
        assert_eq!(principal(old).unwrap().worker_id.as_deref(), Some("old"));
        assert!(principal(new).is_none());
        replace(serde_json::json!([old_grant, new_grant]));
        assert_eq!(principal(old).unwrap().project_id.as_deref(), Some("p"));
        let added = principal(new).unwrap();
        assert_eq!(added.worker_id.as_deref(), Some("new"));
        assert_eq!(added.project_id.as_deref(), Some("q"));
        assert!(auth.worker_scope(&added, Some("old"), Some("q")).is_err());
        replace(serde_json::json!([new_grant]));
        assert!(
            principal(old).is_none(),
            "removed grant must be revoked immediately"
        );
        assert!(
            principal(master).is_none(),
            "configured mode has no fleet fallback"
        );
        std::fs::write(&path, b"malformed").unwrap();
        assert!(principal(new).is_none());
        assert!(principal(master).is_none());
        assert!(
            !principal(owner).unwrap().worker,
            "Owner can repair invalid grants"
        );
        replace(serde_json::json!([new_grant]));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(principal(new).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }
}

pub async fn guard(State(auth): State<Auth>, mut req: Request, next: Next) -> Response {
    if let Some(origin) = req.headers().get("origin").and_then(|v| v.to_str().ok()) {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if origin != format!("http://{host}") && origin != format!("https://{host}") {
            return (
                StatusCode::FORBIDDEN,
                Json(forgeflow_domain::DomainError::new(
                    "ORIGIN_REJECTED",
                    "request origin must match service origin",
                )),
            )
                .into_response();
        }
    }
    // MatchedPath is the router's template, not a caller-controlled resource ID.
    // Missing template never grants a Worker role. Nested API prefix is stripped.
    let matched = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("");
    let route = matched.strip_prefix("/api/v1").unwrap_or(matched);
    let worker_route = matches!(
        (req.method().as_str(), route),
        (
            "POST",
            "/workers/register"
                | "/workers/{worker}/heartbeat"
                | "/workers/{worker}/claim"
                | "/attempts/{attempt}/heartbeat"
                | "/attempts/{attempt}/worker-events"
                | "/attempts/{attempt}/execution-result"
                | "/attempts/{attempt}/handoff-result"
                | "/attempts/{attempt}/author-stop-observation"
                | "/attempts/{attempt}/native-controller"
                | "/attempts/{attempt}/native-model"
                | "/attempts/{attempt}/gateway-scope"
        ) | (
            "GET" | "HEAD",
            "/workers/{worker}/dispatch-events"
                | "/attempts/{attempt}"
                | "/attempts/{attempt}/control"
                | "/attempts/{attempt}/bindings"
                | "/attempts/{attempt}/execution-bindings"
                | "/artifacts/{artifact}/content"
        )
    );
    let draining_route = matches!(
        (req.method().as_str(), route),
        (
            "POST",
            "/workers/{worker}/heartbeat"
                | "/attempts/{attempt}/heartbeat"
                | "/attempts/{attempt}/worker-events"
                | "/attempts/{attempt}/execution-result"
                | "/attempts/{attempt}/handoff-result"
                | "/attempts/{attempt}/author-stop-observation"
                | "/attempts/{attempt}/native-controller"
        )
    );
    let mutating = !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    let Some(principal) = auth.authenticate(req.headers(), mutating) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(forgeflow_domain::DomainError::new(
                "AUTHENTICATION_REQUIRED",
                "valid owner session or service token required",
            )),
        )
            .into_response();
    };
    if auth.is_shutting_down() && mutating {
        let draining_worker = principal.worker && draining_route;
        if !draining_worker {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(forgeflow_domain::DomainError::new(
                    "SERVER_DRAINING",
                    "new commands are stopped while durable processes settle",
                )),
            )
                .into_response();
        }
    }
    if principal.worker && !worker_route {
        return (
            StatusCode::FORBIDDEN,
            Json(forgeflow_domain::DomainError::new(
                "FORBIDDEN",
                "worker token cannot issue owner commands",
            )),
        )
            .into_response();
    }
    req.extensions_mut().insert(principal);
    next.run(req).await
}
