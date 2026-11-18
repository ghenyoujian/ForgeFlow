//! Pinned shared deployment inputs expand into the existing canonical WorkerConfig.
//! These references change disk layout only; no alternate execution/profile authority.
use crate::WorkerConfig;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::{io::Read, path::Path};

fn bounded_json(path: &Path) -> Result<(Value, Vec<u8>)> {
    const LIMIT: u64 = 32 * 1024 * 1024;
    if !path.is_absolute()
        || path.canonicalize()?.as_path() != path
        || !std::fs::symlink_metadata(path)?.is_file()
    {
        bail!("configuration input must be an absolute canonical regular file");
    }
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > LIMIT {
        bail!("configuration input exceeds its byte bound");
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        bail!("configuration input exceeds its byte bound");
    }
    Ok((
        serde_json::from_slice(&bytes).context("invalid configuration JSON")?,
        bytes,
    ))
}

pub fn load_configuration(path: &Path) -> Result<WorkerConfig> {
    let path = path.canonicalize()?;
    let (mut value, _) = bounded_json(&path)?;
    for (reference, target) in [
        ("profile_ref", "profile"),
        ("managed_dsh_ref", "managed_dsh"),
    ] {
        let Some(pin) = value.get(reference).cloned() else {
            continue;
        };
        if value.get(target).is_some() || pin.as_object().is_none_or(|v| v.len() != 2) {
            bail!("shared configuration requires one unambiguous path/sha256 reference");
        }
        let path = pin["path"]
            .as_str()
            .context("shared configuration path missing")?;
        let expected = pin["sha256"]
            .as_str()
            .context("shared configuration digest missing")?;
        if !forgeflow_domain::valid_digest(expected) {
            bail!("invalid shared configuration digest");
        }
        let (resolved, bytes) = bounded_json(Path::new(path))?;
        if forgeflow_executors::sha256(&bytes) != expected {
            bail!("shared configuration input changed");
        }
        let object = value
            .as_object_mut()
            .context("Worker configuration must be an object")?;
        object.remove(reference);
        object.insert(target.into(), resolved);
    }
    serde_json::from_value(value).context("invalid Worker configuration")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shared_profile_preserves_legacy_shape_and_rejects_tamper_or_shadowing() {
        let dir = tempfile::tempdir().unwrap();
        let original = crate::tests::liveness_config("http://127.0.0.1:1234", dir.path());
        let mut value = serde_json::to_value(&original).unwrap();
        let profile = value.as_object_mut().unwrap().remove("profile").unwrap();
        let path = dir.path().join("profile.json");
        let bytes = serde_json::to_vec(&profile).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        value["profile_ref"] = json!({"path":path,"sha256":forgeflow_executors::sha256(&bytes)});
        let config = dir.path().join("worker.json");
        std::fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
        let expanded = load_configuration(&config).unwrap();
        assert_eq!(
            serde_json::to_value(expanded).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        std::fs::write(&path, b"{}").unwrap();
        assert!(load_configuration(&config).is_err());
        std::fs::write(&path, bytes).unwrap();
        value["profile"] = profile;
        std::fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load_configuration(&config).is_err());
    }
}
