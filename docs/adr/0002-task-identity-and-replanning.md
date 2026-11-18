# Task identity and replanning

The task semantic input digest excludes `flow_revision`; the complete Flow semantic digest still binds its revision. A new planning revision may carry an unchanged task without changing its meaning. Historical digests and Attempt snapshots remain immutable and keep their original Flow identities.

An active task may be carried into a new Flow only if the authoritative transaction establishes equivalent task revision, TaskSpec, input digest, Owner and territory, resources, dependency and contract identities, pinned envelope, base SHA, prompt/context manifests, executor/resource/verification profiles, and all required requirement/source/input meanings. Equality of display names or IDs cannot substitute for equality of referenced immutable content. Every accepted Attempt continues to resolve its original immutable task revision and inputs.

Changing an active task requires an explicit stop/finish policy and a new legitimate attempt; a Flow edit never reauthorizes an old process. The store rechecks this rule inside its transaction. Positive and negative independent fixtures must cover unchanged carry-forward and changed-reference rejection before the behavior earns qualification.

Process exit does not release the activity channel. The Worker retains occupied identities and continues exact-identity lease renewal through verification and integration until an authoritative terminal state and confirmed process cleanup. Uncertain cleanup remains quarantined. Independent verifier processes have their own cancellation and expiry supervision; an author process stop cannot stand in for verifier cleanup.

## Generated artifact hashes

Task input identity binds original semantic task/source/input meanings. It excludes hashes of generated prompt/context/verification artifacts whose bytes contain the task input identity, avoiding a circular hash definition. A separate versioned Flow approval identity binds the complete static execution template, including generated artifact and profile/plan hashes. Runtime-issued operation/attempt/lease/generation/worker/timestamp identities are excluded from template normalization. The prompt may contain the task input digest but never the final Flow approval digest. Static template changes are visible in the diff and require a new task revision and approval even when the original input digest is unchanged. The store accepts only the exact frozen template and preserves all historical identities.
