//! One durable pre-author authority; compatibility files are recoverable views.
use super::{ResultDeliveryPolicy, WorkerConfig};
use anyhow::{Context, Result, bail};
use forgeflow_domain::ExecutionEnvelope;
use forgeflow_executors::sha256;
use forgeflow_runtime::Journal;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};

const BUNDLE: &str = "attempt-preparation.json";
const SCHEMA: &str = "forgeflow.worker-attempt-preparation.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Content {
    envelope: ExecutionEnvelope,
    execution_id: String,
    delivery_policy: ResultDeliveryPolicy,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema_version: String,
    payload_sha256: String,
    content: Content,
}

/// Only `prepare` can construct this result, after validating the durable winner
/// and every compatibility view. It is scoped to one preparation invocation.
pub(crate) struct PreparedAuthority {
    execution_id: String,
}

impl PreparedAuthority {
    pub(crate) fn execution_id(&self) -> &str {
        &self.execution_id
    }
}

fn validate(bundle: &Bundle) -> Result<()> {
    let content = &bundle.content;
    content.envelope.validate()?;
    uuid::Uuid::parse_str(&content.execution_id).context("preparation UUID invalid")?;
    if bundle.schema_version != SCHEMA
        || bundle.payload_sha256 != sha256(&serde_json::to_vec(content)?)
        || content.execution_id == content.envelope.operation_id
        || content.delivery_policy.project_id != content.envelope.project_id
        || content.delivery_policy.task_id != content.envelope.task_id
        || content.delivery_policy.attempt_id != content.envelope.attempt_id
        || content.delivery_policy.generation != content.envelope.generation
        || content.delivery_policy.worker_id != content.envelope.worker_id
    {
        bail!("preparation schema, digest or immutable identity drift");
    }
    Ok(())
}

fn read(journal: &Journal) -> Result<Option<Bundle>> {
    let path = journal.path(BUNDLE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("preparation authority must be a private regular file");
    }
    let bundle = serde_json::from_slice(&fs::read(path)?)?;
    validate(&bundle)?;
    Ok(Some(bundle))
}

/// Publish fully synced bytes without replacing another caller's authority.
/// The winning UUID and policy are reused by concurrent duplicate deliveries.
fn publish(journal: &Journal, bundle: &Bundle) -> Result<()> {
    durable_first_json(&journal.path(BUNDLE), &serde_json::to_value(bundle)?)
}

/// Fsync complete bytes before create-new publication; concurrent observers may
/// reuse but never replace the first actual durable authority/observation.
pub(crate) fn durable_first_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().context("durable authority has no parent")?;
    let temporary = parent.join(format!(".authority-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(&temporary)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// These files are caches of the fully fsynced bundle, never separate authority.
/// Atomic replacement avoids partially visible bytes. Missing caches are rebuilt;
/// existing changed bytes are retained and rejected, including identity drift.
fn view(path: &Path, expected: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || fs::read(path)? != expected
            {
                bail!("preparation compatibility view drift: {}", path.display());
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temporary = path.with_extension(format!("{}.view.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(expected)?;
        // Durability comes from BUNDLE, which contains these exact bytes' values.
        // Requiring another checkpoint for a reconstructible view would restore
        // the serial startup IO that this authority deliberately replaces.
        match fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if fs::read(path)? != expected {
                    bail!("concurrent preparation view differs: {}", path.display());
                }
            }
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(&temporary)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn restore_views(journal: &Journal, bundle: &Bundle) -> Result<()> {
    let content = &bundle.content;
    view(
        &journal.path("envelope.json"),
        &serde_json::to_vec(&content.envelope)?,
    )?;
    view(
        &journal.path("execution-id.json"),
        &serde_json::to_vec(&serde_json::json!({"execution_id":content.execution_id}))?,
    )?;
    view(
        &journal.path("result-delivery-policy.json"),
        &serde_json::to_vec(&content.delivery_policy)?,
    )?;
    Ok(())
}

/// Called before callbacks or preparation. Journals created before this feature
/// retain their original policy and execution identity without being migrated.
pub(crate) fn prepare(
    config: &WorkerConfig,
    envelope: &ExecutionEnvelope,
    journal: &Journal,
    admitting: bool,
) -> Result<Option<PreparedAuthority>> {
    let bundle = if let Some(bundle) = read(journal)? {
        bundle
    } else {
        if !admitting {
            return Ok(None);
        }
        fs::create_dir_all(&journal.directory)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&journal.directory, fs::Permissions::from_mode(0o700))?;
        let content = Content {
            envelope: envelope.clone(),
            execution_id: uuid::Uuid::new_v4().to_string(),
            delivery_policy: ResultDeliveryPolicy {
                project_id: envelope.project_id.clone(),
                task_id: envelope.task_id.clone(),
                attempt_id: envelope.attempt_id.clone(),
                generation: envelope.generation,
                worker_id: envelope.worker_id.clone(),
                strict_resource_handoff: config.strict_resource_handoff,
            },
        };
        let bundle = Bundle {
            schema_version: SCHEMA.into(),
            payload_sha256: sha256(&serde_json::to_vec(&content)?),
            content,
        };
        validate(&bundle)?;
        publish(journal, &bundle)?;
        // Concurrent publication may have selected another UUID. Read the
        // actual durable winner instead of reusing our losing candidate.
        read(journal)?.context("durable preparation authority disappeared")?
    };
    if bundle.content.envelope != *envelope {
        bail!("duplicate attempt changed its preparation envelope");
    }
    restore_views(journal, &bundle)?;
    Ok(Some(PreparedAuthority {
        execution_id: bundle.content.execution_id,
    }))
}

pub(crate) fn restore(journal: &Journal) -> Result<Option<ExecutionEnvelope>> {
    let Some(bundle) = read(journal)? else {
        return Ok(None);
    };
    if journal.directory.file_name().and_then(|s| s.to_str())
        != Some(bundle.content.envelope.attempt_id.as_str())
    {
        bail!("preparation directory/attempt identity mismatch");
    }
    restore_views(journal, &bundle)?;
    Ok(Some(bundle.content.envelope))
}

pub(crate) fn policy(
    journal: &Journal,
    envelope: &ExecutionEnvelope,
) -> Result<Option<ResultDeliveryPolicy>> {
    let Some(bundle) = read(journal)? else {
        return Ok(None);
    };
    if bundle.content.envelope != *envelope {
        bail!("preparation policy/envelope binding drift");
    }
    restore_views(journal, &bundle)?;
    Ok(Some(bundle.content.delivery_policy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn missing_views_recover_exact_frozen_identity_and_policy() {
        let temp = tempfile::tempdir().unwrap();
        let envelope = crate::tests::liveness_envelope();
        let mut config = crate::tests::liveness_config("http://127.0.0.1:1", temp.path());
        config.strict_resource_handoff = true;
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        prepare(&config, &envelope, &journal, true).unwrap();
        let authority = fs::read(journal.path(BUNDLE)).unwrap();
        let execution_id = journal.execution_id().unwrap();
        for name in [
            "envelope.json",
            "execution-id.json",
            "result-delivery-policy.json",
        ] {
            fs::remove_file(journal.path(name)).unwrap();
        }
        config.strict_resource_handoff = false;
        assert_eq!(restore(&journal).unwrap(), Some(envelope.clone()));
        assert!(
            policy(&journal, &envelope)
                .unwrap()
                .unwrap()
                .strict_resource_handoff
        );
        assert_eq!(journal.execution_id().unwrap(), execution_id);
        assert_eq!(fs::read(journal.path(BUNDLE)).unwrap(), authority);
        assert!(matches!(
            journal.disposition().unwrap(),
            forgeflow_runtime::RecoveryDisposition::NeverLaunched
        ));
    }

    #[test]
    fn corrupted_authority_and_changed_views_are_retained_and_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let envelope = crate::tests::liveness_envelope();
        let config = crate::tests::liveness_config("http://127.0.0.1:1", temp.path());
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        prepare(&config, &envelope, &journal, true).unwrap();
        let original = fs::read(journal.path(BUNDLE)).unwrap();
        let mut corrupt: Bundle = serde_json::from_slice(&original).unwrap();
        corrupt.content.execution_id = uuid::Uuid::new_v4().to_string();
        fs::write(journal.path(BUNDLE), serde_json::to_vec(&corrupt).unwrap()).unwrap();
        assert!(restore(&journal).is_err());
        fs::write(journal.path(BUNDLE), original).unwrap();
        let changed = br#"{"execution_id":"changed"}"#;
        fs::write(journal.path("execution-id.json"), changed).unwrap();
        assert!(restore(&journal).is_err());
        assert_eq!(
            fs::read(journal.path("execution-id.json")).unwrap(),
            changed
        );
        let mut drifted = envelope.clone();
        drifted.generation += 1;
        assert!(prepare(&config, &drifted, &journal, true).is_err());
    }

    #[test]
    fn concurrent_deliveries_publish_one_immutable_execution_uuid() {
        let temp = tempfile::tempdir().unwrap();
        let envelope = crate::tests::liveness_envelope();
        let config = crate::tests::liveness_config("http://127.0.0.1:1", temp.path());
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        let barrier = Arc::new(Barrier::new(4));
        let handles = (0..4)
            .map(|_| {
                let (config, envelope, journal, barrier) = (
                    config.clone(),
                    envelope.clone(),
                    journal.clone(),
                    barrier.clone(),
                );
                std::thread::spawn(move || {
                    barrier.wait();
                    prepare(&config, &envelope, &journal, true).unwrap();
                    journal.execution_id().unwrap()
                })
            })
            .collect::<Vec<_>>();
        let ids = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>();
        assert!(ids.iter().all(|id| id == &ids[0]));
        assert_eq!(
            read(&journal).unwrap().unwrap().content.execution_id,
            ids[0]
        );
    }

    #[test]
    fn legacy_journal_without_bundle_keeps_existing_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let envelope = crate::tests::liveness_envelope();
        let config = crate::tests::liveness_config("http://127.0.0.1:1", temp.path());
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        fs::create_dir_all(&journal.directory).unwrap();
        let original = b"legacy unchanged";
        fs::write(journal.path("result-delivery-policy.json"), original).unwrap();
        assert!(
            prepare(&config, &envelope, &journal, false)
                .unwrap()
                .is_none()
        );
        assert!(restore(&journal).unwrap().is_none());
        assert_eq!(
            fs::read(journal.path("result-delivery-policy.json")).unwrap(),
            original
        );
        assert!(!journal.path(BUNDLE).exists());
    }
}
