//! Worker-facing façade for the fail-closed ECP child authority.
//!
//! The actual attenuation and lifecycle state machine lives in `forgeflow-runtime`
//! so reconnecting Workers and native controllers share the same semantics.

pub use forgeflow_runtime::ecp_child_supervision::{
    ChildAuthorityError, ChildLifecycleState, ChildReceipt, ChildRequest, ChildScope,
    ChildSupervisor,
};

/// Derive a child scope from a frozen parent scope. This helper keeps Worker
/// call sites explicit: no child is admitted by copying a mutable profile.
pub fn derive_child_scope(
    parent: &ChildScope,
    request: ChildRequest,
) -> Result<ChildScope, ChildAuthorityError> {
    parent.attenuate(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn worker_facade_uses_runtime_attenuation() {
        let parent = ChildScope {
            parent_id: "root".into(),
            child_id: "session".into(),
            project_id: "p".into(),
            generation: 1,
            epoch: 1,
            depth: 0,
            max_depth: 1,
            actions: ["read".into()].into_iter().collect(),
            write_set: BTreeSet::new(),
            budget: BTreeMap::new(),
        };
        let child = derive_child_scope(
            &parent,
            ChildRequest {
                child_id: "child".into(),
                project_id: "p".into(),
                parent_generation: 1,
                parent_epoch: 1,
                actions: ["read".into()].into_iter().collect(),
                write_set: BTreeSet::new(),
                budget: BTreeMap::new(),
            },
        )
        .unwrap();
        assert_eq!(child.parent_id, "session");
    }
}
