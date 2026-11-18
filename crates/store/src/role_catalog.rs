//! Project-sized native rosters. The pinned catalog, not a product constant, is authoritative.
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) fn valid_catalog(catalog: &Value, project: &str) -> bool {
    let Some(roster) = catalog["roster"].as_array() else {
        return false;
    };
    if catalog["schema_version"] != "forgeflow.agent-roles.v1"
        || catalog["project_id"].as_str() != Some(project)
        || !(1..=10_000).contains(&roster.len())
        || catalog["positions"].as_u64() != Some(roster.len() as u64)
    {
        return false;
    }
    let mut positions = BTreeSet::new();
    let mut presets = BTreeSet::new();
    let mut names = BTreeSet::new();
    for row in roster {
        let identity = |key: &str| {
            row[key].as_str().filter(|id| {
                !id.is_empty()
                    && id.len() <= 128
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            })
        };
        let (Some(position), Some(preset), Some(name), Some(_), Some(_)) = (
            identity("position_id"),
            identity("preset_id"),
            identity("teammate_name"),
            identity("owner_id"),
            identity("owner_team_id"),
        ) else {
            return false;
        };
        if !positions.insert(position) || !presets.insert(preset) || !names.insert(name) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn catalog(n: usize) -> Value {
        json!({"schema_version":"forgeflow.agent-roles.v1","project_id":"fresh","positions":n,
            "roster":(0..n).map(|i| json!({"position_id":format!("R-{i}"),"preset_id":format!("preset-{i}"),
                "teammate_name":format!("member-{i}"),"owner_id":"owner","owner_team_id":"team"})).collect::<Vec<_>>()})
    }
    #[test]
    fn arbitrary_sizes_include_hundred_agent_campaign() {
        for n in [1, 4, 10, 58, 100, 128, 256] {
            assert!(valid_catalog(&catalog(n), "fresh"));
        }
    }
    #[test]
    fn wrong_project_count_duplicates_and_empty_are_rejected() {
        assert!(!valid_catalog(&catalog(0), "fresh"));
        assert!(!valid_catalog(&catalog(128), "other"));
        let mut value = catalog(128);
        value["positions"] = json!(58);
        assert!(!valid_catalog(&value, "fresh"));
        let mut value = catalog(128);
        value["roster"][127] = value["roster"][0].clone();
        assert!(!valid_catalog(&value, "fresh"));
    }
}
