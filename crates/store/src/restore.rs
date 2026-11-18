use super::*;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryRelocation {
    project_id: String,
    old_path: String,
    new_path: String,
    main_sha: String,
}
impl Store {
    /// Trusted offline-restoration maintenance. Ordinary project commands never relocate authority.
    pub async fn restore_relocate(
        &self,
        old_data_root: &str,
        new_data_root: &str,
        repositories: Value,
        manifest_hash: &str,
    ) -> Result<CommandReceipt> {
        if !Path::new(old_data_root).is_absolute()
            || !Path::new(new_data_root).is_absolute()
            || !valid_digest(manifest_hash)
        {
            return Err(err(
                "VALIDATION_ERROR",
                "restore roots must be absolute and manifest hash must be SHA256",
            ));
        }
        let request = serde_json::json!({"old_data_root":old_data_root,"new_data_root":new_data_root,"repositories":repositories,"manifest_hash":manifest_hash});
        if let Some(row)=sqlx::query("SELECT request,response FROM idempotency_records WHERE actor_id='restore-service' AND operation='restore_relocate' AND idempotency_key=$1").bind(manifest_hash).fetch_optional(&self.pool).await?{if row.get::<Value,_>("request")!=request{return Err(err("IDEMPOTENCY_CONFLICT","restore manifest key reused for a different mapping"));}let mut receipt:CommandReceipt=decode(row.try_get("response")?)?;receipt.replayed=true;return Ok(receipt)}
        let new_root = std::fs::canonicalize(new_data_root)
            .map_err(|e| err("RESTORE_MAPPING_INCOMPLETE", e.to_string()))?;
        let mappings: Vec<RepositoryRelocation> = decode(repositories.clone())?;
        let mut by_project = BTreeMap::new();
        for mapping in mappings {
            if !Path::new(&mapping.old_path).is_absolute()
                || !Path::new(&mapping.new_path).is_absolute()
                || !valid_sha(&mapping.main_sha)
            {
                return Err(err(
                    "VALIDATION_ERROR",
                    "repository relocation requires absolute paths and exact main SHA",
                ));
            }
            let real = std::fs::canonicalize(&mapping.new_path)
                .map_err(|e| err("RESTORE_MAPPING_INCOMPLETE", e.to_string()))?;
            let head = forgeflow_git::resolve(&real, "refs/heads/main")
                .map_err(|e| err("RESTORE_REF_MISMATCH", e.to_string()))?;
            if head != mapping.main_sha {
                return Err(err(
                    "RESTORE_REF_MISMATCH",
                    "restored main does not equal backup manifest",
                ));
            }
            if by_project
                .insert(mapping.project_id.clone(), (mapping, real))
                .is_some()
            {
                return Err(err("VALIDATION_ERROR", "duplicate restore project mapping"));
            }
        }
        let projects = self.list_projects().await?;
        for project in &projects {
            if !project.paused {
                return Err(err(
                    "RESTORE_NOT_QUIESCENT",
                    "all projects must remain paused during relocation",
                ));
            }
            if project.authority_mode == AuthorityMode::Managed
                && !by_project.contains_key(&project.project_id)
            {
                return Err(err(
                    "RESTORE_MAPPING_INCOMPLETE",
                    "every managed repository needs reviewed backup main identity",
                ));
            }
            if let Some((mapping, _)) = by_project.get(&project.project_id) {
                if mapping.old_path != project.root_path
                    && Path::new(&project.root_path) != by_project[&project.project_id].1.as_path()
                {
                    return Err(err(
                        "REVISION_CONFLICT",
                        "backup root mapping differs from restored project authority",
                    ));
                }
            }
        }
        if by_project
            .keys()
            .any(|p| !projects.iter().any(|project| &project.project_id == p))
        {
            return Err(err(
                "NOT_FOUND",
                "restore mapping references unknown project",
            ));
        }
        let artifact_rows=sqlx::query("SELECT project_id,document_id,revision,data FROM documents WHERE collection='artifacts' ORDER BY project_id,document_id").fetch_all(&self.pool).await?;
        let mut artifacts = Vec::new();
        for row in artifact_rows {
            let data: Value = row.try_get("data")?;
            let Some(path) = data.get("path").and_then(Value::as_str) else {
                continue;
            };
            let path = Path::new(path);
            let new_path = if path.starts_with(&new_root)
                || by_project.values().any(|(_, repo)| path.starts_with(repo))
            {
                path.to_path_buf()
            } else if let Ok(relative) = path.strip_prefix(old_data_root) {
                new_root.join(relative)
            } else {
                let mapping = by_project.values().find_map(|(mapping, real)| {
                    path.strip_prefix(&mapping.old_path)
                        .ok()
                        .map(|relative| real.join(relative))
                });
                mapping.ok_or_else(|| {
                    err(
                        "RESTORE_MAPPING_INCOMPLETE",
                        "artifact path is outside reviewed data/repository roots",
                    )
                })?
            };
            let real = std::fs::canonicalize(&new_path)
                .map_err(|e| err("RESTORE_ARTIFACT_MISMATCH", e.to_string()))?;
            let allowed = real.starts_with(&new_root)
                || by_project.values().any(|(_, repo)| real.starts_with(repo));
            if !allowed {
                return Err(err(
                    "OWNER_PATH_VIOLATION",
                    "restored artifact symlink escapes reviewed storage roots",
                ));
            }
            let expected = data
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| err("RESTORE_ARTIFACT_MISMATCH", "artifact lacks immutable hash"))?;
            if hash_file(&real)? != expected {
                return Err(err(
                    "RESTORE_ARTIFACT_MISMATCH",
                    "restored artifact bytes differ from history",
                ));
            }
            artifacts.push((
                row.try_get::<String, _>("project_id")?,
                row.try_get::<String, _>("document_id")?,
                row.try_get::<i64, _>("revision")?,
                data,
                real,
            ));
        }

        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        if let Some(value) = replay(
            &mut tx,
            "restore-service",
            "restore_relocate",
            manifest_hash,
            &request,
        )
        .await?
        {
            let mut result: CommandReceipt = decode(value)?;
            result.replayed = true;
            tx.commit().await?;
            return Ok(result);
        }
        let active: i64 =
            sqlx::query_scalar("SELECT count(*) FROM attempts WHERE terminal_at IS NULL")
                .fetch_one(&mut *tx)
                .await?;
        let model: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM model_request_permit WHERE status IN('ADMITTED','QUARANTINED')",
        )
        .fetch_one(&mut *tx)
        .await?;
        if active != 0 || model != 0 {
            return Err(err(
                "RESTORE_NOT_QUIESCENT",
                "restore cannot relocate active attempts or unknown model effects",
            ));
        }
        let operation_id = id();
        let mut last_revision = 0;
        for before in projects {
            let mut project = project_lock(&mut tx, &before.project_id).await?;
            if project.revision != before.revision || !project.paused {
                return Err(err(
                    "REVISION_CONFLICT",
                    "project changed during relocation preflight",
                ));
            }
            if let Some((mapping, real)) = by_project.get(&project.project_id) {
                if mapping.old_path != project.root_path {
                    return Err(err("REVISION_CONFLICT", "project root changed"));
                }
                if project.authority_mode == AuthorityMode::Managed && !project.archived {
                    crate::catalog::assert_managed_repository_unique(
                        &mut tx,
                        &project.project_id,
                        &real.to_string_lossy(),
                    )
                    .await?;
                }
                project.root_path = real.to_string_lossy().into_owned();
                project.revision += 1;
                last_revision = project.revision;
                sqlx::query("UPDATE projects SET revision=$2,data=$3 WHERE project_id=$1")
                    .bind(&project.project_id)
                    .bind(i64v(project.revision)?)
                    .bind(json(&project)?)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("INSERT INTO project_revisions VALUES($1,$2,$3)")
                    .bind(&project.project_id)
                    .bind(i64v(project.revision)?)
                    .bind(json(&project)?)
                    .execute(&mut *tx)
                    .await?;
                event(&mut tx,&project.project_id,&project.project_id,project.revision,"project.restore_relocated",serde_json::json!({"old_path":mapping.old_path,"new_path":project.root_path,"main_sha":mapping.main_sha,"manifest_hash":manifest_hash,"operation_id":operation_id})).await?;
            }
        }
        for (project, artifact, revision, mut before, path) in artifacts {
            let current:Option<Value>=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2 AND revision=$3 FOR UPDATE").bind(&project).bind(&artifact).bind(revision).fetch_optional(&mut *tx).await?;
            if current.as_ref() != Some(&before) {
                return Err(err(
                    "REVISION_CONFLICT",
                    "artifact locator changed during preflight",
                ));
            }
            let old_path = before["path"].clone();
            before["path"] = path.to_string_lossy().into_owned().into();
            before["revision"] = (revision + 1).into();
            sqlx::query("UPDATE documents SET revision=revision+1,data=$3 WHERE project_id=$1 AND collection='artifacts' AND document_id=$2").bind(&project).bind(&artifact).bind(&before).execute(&mut *tx).await?;
            event(&mut tx,&project,&artifact,(revision+1) as u64,"artifact.restore_locator_relocated",serde_json::json!({"old_path":old_path,"new_path":before["path"],"sha256":before["sha256"],"manifest_hash":manifest_hash,"operation_id":operation_id})).await?;
        }
        let result = CommandReceipt {
            operation_id: operation_id.clone(),
            status: "RELOCATED_REVIEW_REQUIRED".into(),
            object_id: manifest_hash.into(),
            revision: last_revision,
            replayed: false,
        };
        save_replay(
            &mut tx,
            "restore-service",
            "restore_relocate",
            manifest_hash,
            &operation_id,
            &request,
            &json(&result)?,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
}
fn hash_file(path: &PathBuf) -> Result<String> {
    use sha2::Digest;
    use std::io::Read;
    let mut file =
        std::fs::File::open(path).map_err(|e| err("RESTORE_ARTIFACT_MISMATCH", e.to_string()))?;
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| err("RESTORE_ARTIFACT_MISMATCH", e.to_string()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
