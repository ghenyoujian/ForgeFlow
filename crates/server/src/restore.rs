//! Offline reviewed path relocation. No network listener or execution actor.
use forgeflow_store::Store;
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path};

const MANIFEST_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelocationManifest {
    old_data_root: String,
    new_data_root: String,
    repositories: Vec<RepositoryRelocation>,
    manifest_hash: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryRelocation {
    project_id: String,
    old_path: String,
    new_path: String,
    main_sha: String,
}

/// Hash input is exactly serde_json's compact UTF8 serialization of this
/// ordered payload, without manifest_hash or trailing newline. Repository
/// arrays retain supplied order; each entry serializes project_id, old_path,
/// new_path, main_sha in that order. The algorithm is
/// SHA256_CANONICAL_FORGEFLOW_RELOCATION_PAYLOAD_V1, not a self-referential hash.
#[derive(Serialize)]
struct RelocationPayload<'a> {
    old_data_root: &'a str,
    new_data_root: &'a str,
    repositories: &'a [RepositoryRelocation],
}

pub(crate) async fn relocate(
    store: &Store,
    manifest_path: &Path,
    data_root: &Path,
) -> anyhow::Result<forgeflow_domain::CommandReceipt> {
    anyhow::ensure!(
        manifest_path.is_absolute(),
        "restore relocation manifest path must be absolute"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(manifest_path)?
        .take(MANIFEST_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MANIFEST_LIMIT,
        "restore relocation manifest exceeds 4 MiB"
    );
    let manifest: RelocationManifest = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        Path::new(&manifest.old_data_root).is_absolute()
            && Path::new(&manifest.new_data_root).is_absolute(),
        "restore data roots must be absolute"
    );
    anyhow::ensure!(
        manifest.repositories.len() <= 10_000,
        "restore relocation exceeds 10000 repository mappings"
    );
    anyhow::ensure!(
        manifest.manifest_hash.len() == 64
            && manifest
                .manifest_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "restore manifest_hash must be lowercase SHA256"
    );
    let payload = RelocationPayload {
        old_data_root: &manifest.old_data_root,
        new_data_root: &manifest.new_data_root,
        repositories: &manifest.repositories,
    };
    let digest = forgeflow_evidence::sha256(&serde_json::to_vec(&payload)?);
    anyhow::ensure!(
        digest == manifest.manifest_hash,
        "restore relocation canonical payload SHA256 mismatch"
    );
    let destination = std::fs::canonicalize(&manifest.new_data_root)?;
    anyhow::ensure!(
        destination == std::fs::canonicalize(data_root)?,
        "restore new_data_root differs from --data-root"
    );
    // This existing authority command verifies every paused project, complete
    // managed mapping, exact restored main, retained artifact bytes and inactive
    // effects before atomically updating only reviewed database locators.
    Ok(store
        .restore_relocate(
            &manifest.old_data_root,
            &manifest.new_data_root,
            serde_json::to_value(&manifest.repositories)?,
            &manifest.manifest_hash,
        )
        .await?)
}
