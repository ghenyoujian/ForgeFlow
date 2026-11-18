#!/usr/bin/env python3
"""Independent compact planning oracle. Only Python's standard library is used.

The raw native event and prelaunch inputs are read, never repaired or rewritten.
This oracle checks intent against immutable source/authority facts. It does not
build a DraftBundle, import production code, approve a Flow, or issue a lease.
"""
import copy
import hashlib
import json
import math
import os
import re
from pathlib import Path

ORACLE = "a10-source-bound-planning-intent.v2"
SCHEMA = "forgeflow.planning-intent.v1"
AUTHORITY_SCHEMA = "forgeflow.planning-authority.v1"
MAX_TASKS = 10_000
MAX_NATIVE_BYTES = 32 * 1024 * 1024
RESOURCE_FIELDS = ("active_slot", "coding_slot", "cpu_units", "memory_bytes",
                   "build_permit", "gpu_permit", "provider_inflight")
TASK_REQUIRED = {"task_id", "title", "requirement_ids", "outcome", "read_set",
                 "write_set", "dependencies", "resource_request",
                 "verification_case_count", "rollback_plan"}
TASK_OPTIONAL = {"contract_produces", "contract_consumes", "producer_inputs",
                 "known_unknowns", "not_proven"}
REQUEST_FIELDS = {"project_id", "flow_revision", "source", "owner_id", "team_id",
                  "write_set", "execution_profile", "verification_plan"}
SOURCE_REQUIREMENT_FIELDS = {"project_id", "requirement_id", "title", "source_anchor",
                             "outcome", "scope", "acceptance", "priority", "weight",
                             "deferred_reason", "revision"}
REQUIREMENT_FIELDS = {"requirement_id", "source_document", "anchor", "acceptance",
                      "priority", "deferred_reason"}
AUTHORITY_FIELDS = {"schema_version", "proposal_schema_version", "max_tasks",
                    "source_input", "current_inputs", "requirement_semantic_digests",
                    "owners", "resolved_paths", "contracts", "resources"}
CONTRACT_FIELDS = {"contract_id", "version", "spec_sha256"}
CONTRACT_SNAPSHOT_FIELDS = CONTRACT_FIELDS | {"source_sha256", "frozen",
    "required_consumers", "passing_consumers", "independent_receipt_id",
    "integration_receipt_id"}
POLICY_FIELDS = {"worker_id", "scope_id", "parent_scope_id", "project_id", "team_id",
                 "limits", "revision", "paused"}
BINDING_FIELDS = {"task_revision", "attempt_id", "generation", "verification_plan_id",
                  "verification_plan_hash", "contract_version", "input_hash",
                  "context_hash", "prompt_hash", "artifact_hash"}

# Register these exact cases in a NEW immutable VerificationPlan. Every actual
# artifact must pass the positive cases before mutations can pass any negative.
CASES = {
    "author": [
        ("native_final_artifact", "positive"),
        ("intent_schema_and_source_binding", "positive"),
        ("prelaunch_request_authority_and_input_identity", "positive"),
    ],
    "consumer": [
        ("finite_complete_dag_consumer", "positive"),
        ("cycle_rejected", "negative"),
        ("missing_predecessor_rejected", "negative"),
        ("source_coverage_gap_rejected", "negative"),
        ("unregistered_contract_pin_rejected", "negative"),
    ],
    "independent": [
        ("original_source_meaning_preserved", "positive"),
        ("exact_write_scope_and_owner_bound", "positive"),
        ("request_byte_tamper_rejected", "negative"),
        ("authority_byte_tamper_rejected", "negative"),
        ("source_byte_tamper_rejected", "negative"),
        ("authority_field_injection_rejected", "negative"),
        ("expanded_write_scope_rejected", "negative"),
        ("zero_case_denominator_rejected", "negative"),
        ("invalid_resource_vector_rejected", "negative"),
        ("resource_cap_expansion_rejected", "negative"),
        ("invented_known_input_hash_rejected", "negative"),
        ("strict_duplicate_keys_rejected", "negative"),
        ("truncated_json_rejected", "negative"),
        ("unknown_fields_rejected", "negative"),
        ("protocol_version_mismatch_rejected", "negative"),
        ("stale_context_binding_rejected", "negative"),
        ("source_input_snapshot_mismatch_rejected", "negative"),
    ],
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_load(text):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def constant(value):
        raise ValueError("nonfinite JSON number: " + value)

    def number(value):
        parsed = float(value)
        require(math.isfinite(parsed), "nonfinite JSON number: " + value)
        return parsed

    result = json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=number)
    # Rust UTF-8 Strings cannot contain isolated UTF-16 surrogates. json.loads
    # alone would accept such escaped strings, including authority/path IDs.
    pending = [result]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            require(not any(0xD800 <= ord(c) <= 0xDFFF for c in item), "invalid Unicode scalar")
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return result


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sha_valid(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def uint(value, positive=False):
    return type(value) is int and (1 if positive else 0) <= value < 2**64


def text_valid(value):
    return isinstance(value, str) and bool(value.strip())


def exact_object(value, fields, message):
    require(isinstance(value, dict) and set(value) == set(fields), message)


def strings(value, message, unique=False, nonempty_items=True):
    require(isinstance(value, list) and all(isinstance(v, str) and
            (not nonempty_items or bool(v.strip())) for v in value), message)
    if unique:
        require(len(value) == len(set(value)), message + " duplicates")


def path_valid(path):
    if not isinstance(path, str) or not path or path.startswith("/"):
        return False
    if any(c in path for c in ("\\", ":", "\0")):
        return False
    trimmed = path[:-1] if path.endswith("/") else path
    return bool(trimmed) and all(part not in {"", ".", ".."} for part in trimmed.split("/"))


def covers(scope, path):
    return path == scope or scope.endswith("/") and path.startswith(scope)


def overlaps(left, right):
    return covers(left, right) or covers(right, left)


def paths(value, message):
    strings(value, message, unique=True)
    require(all(path_valid(path) for path in value), message + " must be normalized")


def resource_vector(value, message):
    exact_object(value, RESOURCE_FIELDS, message + " fields")
    require(all(uint(v) for v in value.values()), message + " strict u64 dimensions")


def contract_key(value):
    exact_object(value, CONTRACT_FIELDS, "contract binding fields")
    require(text_valid(value["contract_id"]) and uint(value["version"], positive=True)
            and sha_valid(value["spec_sha256"]), "contract identity")
    return value["contract_id"], value["version"], value["spec_sha256"]


def requirement_digest(requirement):
    """Documented source semantic identity, independent of model normalization."""
    meaning = ["forgeflow.requirement.semantic.v1", requirement["project_id"],
               requirement["requirement_id"], requirement["source_anchor"],
               requirement["outcome"], requirement["scope"], requirement["acceptance"],
               requirement["priority"], requirement["weight"], requirement["deferred_reason"]]
    return sha(json.dumps(meaning, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def decode_pinned(raw, expected_hash, description):
    require(sha_valid(expected_hash) and sha(raw) == expected_hash,
            description + " bytes differ from prelaunch pin")
    return strict_load(raw.decode("utf-8"))


def validate_originals(request, authority, source):
    exact_object(request, REQUEST_FIELDS, "immutable DraftRequest fields")
    require(all(text_valid(request[k]) for k in ("project_id", "owner_id", "team_id",
            "execution_profile", "verification_plan")) and uint(request["flow_revision"], True),
            "immutable request authority/version identities")
    paths(request["write_set"], "approved request write scope")
    source_request = request["source"]
    exact_object(source_request, {"source_document", "raw_sha256", "semantic_sha256", "requirements"},
                 "immutable requirement document fields")
    require(text_valid(source_request["source_document"]) and sha_valid(source_request["raw_sha256"])
            and sha_valid(source_request["semantic_sha256"]), "immutable source document identity")
    exact_object(source, {"documents", "requirements", "manual_requirement_policy"}, "original source bundle")
    require(isinstance(source["documents"], list) and text_valid(source["manual_requirement_policy"]),
            "original source documents and manual policy")
    require(isinstance(source["requirements"], list) and source["requirements"], "source requirements")
    require(isinstance(source_request["requirements"], list), "request source requirements")
    original = {}
    for row in source["requirements"]:
        exact_object(row, SOURCE_REQUIREMENT_FIELDS, "original domain requirement fields")
        require(row["project_id"] == request["project_id"] and text_valid(row["requirement_id"])
                and text_valid(row["source_anchor"]) and isinstance(row["title"], str)
                and isinstance(row["outcome"], str) and isinstance(row["scope"], str),
                "original requirement identities and meaning")
        strings(row["acceptance"], "source acceptance clauses", nonempty_items=False)
        require(type(row["priority"]) is int and -(2**31) <= row["priority"] < 2**31
                and uint(row["weight"]) and uint(row["revision"], True)
                and (row["deferred_reason"] is None or isinstance(row["deferred_reason"], str)),
                "source requirement typed facts")
        rid = row["requirement_id"]
        require(rid not in original, "duplicate original requirement identity")
        original[rid] = row
    projections = {}
    for row in source_request["requirements"]:
        exact_object(row, REQUIREMENT_FIELDS, "request requirement fields")
        rid = row["requirement_id"]
        require(isinstance(rid, str) and rid in original and rid not in projections,
                "exact original requirement identities")
        supplied = original[rid]
        anchor_parts = supplied["source_anchor"].split("#", 1)
        document, anchor = anchor_parts if len(anchor_parts) == 2 else ["manual", anchor_parts[0]]
        require(row == {"requirement_id": rid, "source_document": document, "anchor": anchor,
                "acceptance": "\n".join(supplied["acceptance"]), "priority": supplied["priority"],
                "deferred_reason": supplied["deferred_reason"]}, "original source projection changed")
        projections[rid] = row
    require(set(projections) == set(original), "original source requirement denominator")

    exact_object(authority, AUTHORITY_FIELDS, "prelaunch authority fields")
    require(authority["schema_version"] == AUTHORITY_SCHEMA and authority["proposal_schema_version"] == SCHEMA
            and type(authority["max_tasks"]) is int and authority["max_tasks"] == MAX_TASKS,
            "prelaunch protocol/task scale mismatch")
    input_ref = authority["source_input"]
    exact_object(input_ref, {"path", "sha256", "producer_task_id"}, "source input binding fields")
    require(path_valid(input_ref["path"]) and input_ref["producer_task_id"] is None
            and input_ref["sha256"] == source_request["raw_sha256"], "immutable source input identity")
    require(isinstance(authority["current_inputs"], dict) and all(path_valid(p) and sha_valid(h)
            for p, h in authority["current_inputs"].items()), "current input snapshot identities")
    require(authority["current_inputs"].get(input_ref["path"]) == input_ref["sha256"],
            "original source current-input snapshot mismatch")
    require(authority["requirement_semantic_digests"] ==
            {rid: requirement_digest(row) for rid, row in original.items()},
            "original full source requirement semantic pins")
    require(isinstance(authority["resolved_paths"], dict) and all(path_valid(p) and path_valid(target)
            for p, target in authority["resolved_paths"].items()), "resolved input/write paths")
    owners = {}
    require(isinstance(authority["owners"], list), "registered Owner snapshot")
    for owner in authority["owners"]:
        exact_object(owner, {"owner_id", "root_team_id", "include", "exclude"}, "Owner territory fields")
        require(text_valid(owner["owner_id"]) and text_valid(owner["root_team_id"])
                and owner["owner_id"] not in owners, "unique explicitly rooted Owner")
        paths(owner["include"], "Owner include territory")
        paths(owner["exclude"], "Owner exclude territory")
        owners[owner["owner_id"]] = owner
    require(request["owner_id"] in owners, "request Owner registered before launch")
    validate_resource_authority(authority["resources"], request, owners[request["owner_id"]])
    require(isinstance(authority["contracts"], list), "registered contracts")
    contract_ids = set()
    for contract in authority["contracts"]:
        exact_object(contract, CONTRACT_SNAPSHOT_FIELDS, "contract snapshot fields")
        key = contract_key({field: contract[field] for field in CONTRACT_FIELDS})
        require(key[:2] not in contract_ids and sha_valid(contract["source_sha256"])
                and type(contract["frozen"]) is bool, "registered contract identity")
        contract_ids.add(key[:2])
        strings(contract["required_consumers"], "required contract consumers", unique=True)
        strings(contract["passing_consumers"], "passing contract consumers", unique=True)
        require(all(contract[k] is None or text_valid(contract[k]) for k in
                ("independent_receipt_id", "integration_receipt_id")), "contract receipt identities")
    return original


def validate_resource_authority(resources, request, owner):
    exact_object(resources, {"scope", "scopes", "effective_limits"}, "resource authority fields")
    require(resources["scope"] == "GLOBAL_PROJECT_TEAM_CAPS_ONLY_WORKER_PLACEMENT_UNVERIFIED",
            "resource snapshot has no worker-placement qualification")
    require(isinstance(resources["scopes"], list) and resources["scopes"], "resource policy denominator")
    policies = {}
    for policy in resources["scopes"]:
        exact_object(policy, POLICY_FIELDS, "canonical resource policy fields")
        require(text_valid(policy["scope_id"]) and policy["scope_id"] not in policies
                and policy["worker_id"] is None and uint(policy["revision"], True)
                and type(policy["paused"]) is bool, "captured resource scope identity")
        require(policy["project_id"] in (None, request["project_id"])
                and (policy["team_id"] is None or text_valid(policy["team_id"]))
                and (policy["parent_scope_id"] is None or text_valid(policy["parent_scope_id"])),
                "resource project/team/ancestor identity")
        resource_vector(policy["limits"], "scope approved limits")
        policies[policy["scope_id"]] = policy
    require(any(p["project_id"] is None and p["team_id"] is None for p in policies.values())
            and any(p["project_id"] == request["project_id"] and p["team_id"] is None for p in policies.values())
            and any(p["project_id"] == request["project_id"] and p["team_id"] == request["team_id"]
                    for p in policies.values()), "global/project/selected-team resource scopes")
    team_ids = {p["team_id"] for p in policies.values() if p["team_id"] is not None}
    require(owner["root_team_id"] in team_ids, "Owner root included in captured ancestor scopes")
    for policy in policies.values():
        visited = {policy["scope_id"]}
        parent = policy["parent_scope_id"]
        while parent is not None:
            require(parent in policies and parent not in visited, "resource ancestor gap/cycle")
            visited.add(parent)
            parent = policies[parent]["parent_scope_id"]
    resource_vector(resources["effective_limits"], "effective approved limits")
    require(resources["effective_limits"] == {field: min(p["limits"][field] for p in policies.values())
            for field in RESOURCE_FIELDS}, "effective approved cap differs from captured scopes")


def acyclic_order(tasks):
    """Iterative three-colour traversal; handles deep subplan DAGs without recursion."""
    dependencies = {t["task_id"]: [d["task_id"] for d in t["dependencies"]] for t in tasks}
    known = set(dependencies)
    require(all(set(deps) <= known for deps in dependencies.values()), "missing DAG predecessor")
    colours = {}
    order = []
    for root in dependencies:
        if colours.get(root) == 2:
            continue
        stack = [(root, False)]
        while stack:
            task_id, exiting = stack.pop()
            if exiting:
                colours[task_id] = 2
                order.append(task_id)
                continue
            if colours.get(task_id) == 2:
                continue
            require(colours.get(task_id) != 1, "dependency cycle")
            colours[task_id] = 1
            stack.append((task_id, True))
            for predecessor in reversed(dependencies[task_id]):
                require(colours.get(predecessor) != 1, "dependency cycle")
                if colours.get(predecessor) != 2:
                    stack.append((predecessor, False))
    return order


def validate(intent, request, authority, source):
    original = validate_originals(request, authority, source)
    requirement_ids = set(original)
    exact_object(intent, {"schema_version", "tasks"}, "compact intent fields; authority is forbidden")
    require(intent["schema_version"] == SCHEMA, "compact intent protocol version")
    tasks = intent["tasks"]
    require(isinstance(tasks, list) and 1 <= len(tasks) <= MAX_TASKS, "finite nonempty task denominator")
    selected_owner = next(o for o in authority["owners"] if o["owner_id"] == request["owner_id"])
    registered = {contract_key({field: c[field] for field in CONTRACT_FIELDS}): c
                  for c in authority["contracts"]}
    ids = {}
    covered_requirements = set()
    producers = {}
    for task in tasks:
        require(isinstance(task, dict) and TASK_REQUIRED <= set(task) <= TASK_REQUIRED | TASK_OPTIONAL,
                "compact task fields; model authority/hashes are forbidden")
        task_id = task["task_id"]
        require(isinstance(task_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,48}", task_id)
                and task_id not in ids, "unique short ASCII task identity")
        ids[task_id] = task
        require(all(text_valid(task[k]) for k in ("title", "outcome", "rollback_plan")),
                "finite task outcome/title/rollback")
        require(uint(task["verification_case_count"], True), "nonzero planned case denominator")
        strings(task["requirement_ids"], "task requirement references", unique=True)
        require(task["requirement_ids"] and set(task["requirement_ids"]) <= requirement_ids,
                "task binds exact original requirements")
        covered_requirements.update(task["requirement_ids"])
        for field in ("read_set", "write_set"):
            paths(task[field], "task " + field)
        for path in task["write_set"]:
            target = authority["resolved_paths"].get(path, path)
            require(any(covers(scope, path) for scope in request["write_set"]), "expanded approved write scope")
            require(all(any(covers(scope, p) for scope in selected_owner["include"]) for p in (path, target))
                    and not any(overlaps(scope, p) for scope in selected_owner["exclude"] for p in (path, target)),
                    "write outside original Owner territory/excludes")
            authorized = [o for o in authority["owners"] if any(covers(scope, target) for scope in o["include"])
                          and not any(overlaps(scope, target) for scope in o["exclude"])]
            require(len(authorized) == 1 and authorized[0]["owner_id"] == request["owner_id"],
                    "write path lacks one unique original root Owner")
        resource_vector(task["resource_request"], "task resource request")
        resources = task["resource_request"]
        require(resources["active_slot"] > 0 and (not task["write_set"] or resources["coding_slot"] > 0),
                "positive active/coding reservations")
        require(all(resources[field] <= authority["resources"]["effective_limits"][field]
                    for field in RESOURCE_FIELDS), "task exceeds captured approved resource cap")
        require(isinstance(task["dependencies"], list), "typed dependencies")
        dependency_ids = set()
        for dependency in task["dependencies"]:
            exact_object(dependency, {"task_id", "kind", "binding_id"}, "dependency fields")
            require(text_valid(dependency["task_id"]) and dependency["task_id"] not in dependency_ids
                    and dependency["kind"] in {"integrated", "artifact", "contract_frozen", "gate_pass"}
                    and text_valid(dependency["binding_id"]), "unique typed semantic dependency")
            dependency_ids.add(dependency["task_id"])
        for field in ("known_unknowns", "not_proven"):
            strings(task.get(field, []), "task " + field, nonempty_items=False)
        for field in ("contract_produces", "contract_consumes"):
            require(isinstance(task.get(field, []), list), "contract list")
            keys = [contract_key(c) for c in task.get(field, [])]
            require(len(keys) == len(set(keys)) and all(key in registered for key in keys),
                    "exact registered contract pins")
            if field == "contract_produces":
                for key in keys:
                    require(key[:2] not in producers, "duplicate immutable contract producer")
                    producers[key[:2]] = task_id
            else:
                for key in keys:
                    contract = registered[key]
                    require(contract["frozen"] and contract["required_consumers"]
                            and set(contract["required_consumers"]) <= set(contract["passing_consumers"])
                            and text_valid(contract["independent_receipt_id"])
                            and text_valid(contract["integration_receipt_id"]), "public contract lacks frozen evidence")
    require(all(rid in covered_requirements or text_valid(row["deferred_reason"])
                for rid, row in original.items()), "original source coverage gap")
    order = acyclic_order(tasks)
    for task in tasks:
        future = task.get("producer_inputs", [])
        require(isinstance(future, list), "future producer input list")
        future_paths = set()
        for input_ref in future:
            required = {"path", "producer_task_id", "dependency_binding_id", "contract"}
            optional = {"producer_task_revision", "producer_input_digest"}
            require(isinstance(input_ref, dict) and required <= set(input_ref) <= required | optional,
                    "future input fields; invented byte hashes are forbidden")
            path = input_ref["path"]
            require(path_valid(path) and path not in future_paths and path in task["read_set"]
                    and path != authority["source_input"]["path"], "future input path/read binding")
            future_paths.add(path)
            producer_id = input_ref["producer_task_id"]
            require(isinstance(producer_id, str) and producer_id in ids and producer_id != task["task_id"],
                    "exact future producer identity")
            producer = ids[producer_id]
            pin = contract_key(input_ref["contract"])
            require(pin in registered and input_ref["contract"] in task.get("contract_consumes", [])
                    and input_ref["contract"] in producer.get("contract_produces", [])
                    and any(covers(scope, path) for scope in producer["write_set"]),
                    "future input exact producer path/contract")
            binding_id = input_ref["dependency_binding_id"]
            require(text_valid(binding_id) and any(d["task_id"] == producer_id and d["kind"] == "integrated"
                    and d["binding_id"] == binding_id for d in task["dependencies"]),
                    "future input exact integrated predecessor binding")
            revision = input_ref.get("producer_task_revision")
            digest = input_ref.get("producer_input_digest")
            require(revision is None or uint(revision, True) and revision == 1, "future producer revision pin")
            require(digest is None or sha_valid(digest), "future producer semantic digest pin")
            # Exact canonical semantic digest comparison is mandatory in the
            # existing seal after controller materialization. It is not an
            # invented known-input hash and is never replaced by this oracle.
        require(all(path in future_paths or path in authority["current_inputs"] for path in task["read_set"]),
                "read input absent from immutable snapshot; future bytes need explicit producer binding")
    return order


def validate_binding(binding, env, request, authority):
    exact_object(binding, BINDING_FIELDS, "native artifact evidence binding fields")
    require(uint(binding["task_revision"], True) and binding["task_revision"] == 1
            and type(binding["generation"]) is int and binding["generation"] > 0
            and text_valid(binding["attempt_id"]) and binding["contract_version"] == "none",
            "planning artifact attempt/task revision identity")
    task_id = env["FORGEFLOW_PLANNING_TASK_ID"]
    require(text_valid(task_id) and task_id.startswith("planning-") and len(task_id) > len("planning-"),
            "prelaunch planning task identity")
    operation = task_id[len("planning-"):]
    require(binding["verification_plan_id"] == "planning-verification-" + operation
            and request["source"]["source_document"] == "planning-source-" + operation
            and authority["source_input"]["path"] == "source-artifacts/planning-source-" + operation + ".json",
            "planning task/plan/source identities disagree")
    for field, key in (("input_hash", "FORGEFLOW_PLANNING_INPUT_HASH"),
                       ("context_hash", "FORGEFLOW_PLANNING_CONTEXT_SHA256"),
                       ("prompt_hash", "FORGEFLOW_PLANNING_PROMPT_SHA256")):
        require(sha_valid(binding[field]) and binding[field] == env[key], "stale prelaunch " + field)
    require(sha_valid(binding["verification_plan_hash"]) and sha_valid(binding["artifact_hash"]),
            "registered plan/raw artifact hashes")


def verify_artifact(raw, request_raw, authority_raw, source_raw, env, binding):
    require(0 < len(raw) <= MAX_NATIVE_BYTES, "existing native final 32 MiB bound")
    require(sha(raw) == binding.get("artifact_hash"), "native raw final bytes mismatch")
    request = decode_pinned(request_raw, env["FORGEFLOW_DRAFT_REQUEST_SHA256"], "DraftRequest")
    authority = decode_pinned(authority_raw, env["FORGEFLOW_PLANNING_AUTHORITY_SHA256"], "authority snapshot")
    source = decode_pinned(source_raw, env["FORGEFLOW_PLANNING_SOURCE_SHA256"], "original source")
    require(sha(source_raw) == request["source"]["raw_sha256"], "original source raw SHA256")
    validate_binding(binding, env, request, authority)
    final = strict_load(raw.decode("utf-8"))
    require(isinstance(final, dict) and final.get("type") == "final" and isinstance(final.get("text"), str),
            "native terminal final artifact")
    intent = strict_load(final["text"])
    validate(intent, request, authority, source)
    return intent, request, authority, source


def rejects(call):
    try:
        call()
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError):
        return True
    return False


def changed_intent(intent, change, request, authority, source):
    changed = copy.deepcopy(intent)
    change(changed)
    return rejects(lambda: validate(changed, request, authority, source))


def run_cases(role, raw, request_raw, authority_raw, source_raw, env, binding):
    result = {name: False for name, _ in CASES[role]}
    errors = []
    try:
        intent, request, authority, source = verify_artifact(raw, request_raw, authority_raw, source_raw, env, binding)
        def mutation(name, change):
            result[name] = changed_intent(intent, change, request, authority, source)
        if role == "author":
            result = dict.fromkeys(result, True)
        elif role == "consumer":
            result["finite_complete_dag_consumer"] = True
            mutation("cycle_rejected", lambda p: p["tasks"][0]["dependencies"].append({
                "task_id": p["tasks"][0]["task_id"], "kind": "integrated", "binding_id": "oracle-cycle"}))
            missing = "oracle-missing"
            while any(t["task_id"] == missing for t in intent["tasks"]):
                missing += "-x"
            mutation("missing_predecessor_rejected", lambda p: p["tasks"][0]["dependencies"].append({
                "task_id": missing, "kind": "artifact", "binding_id": "oracle-missing"}))
            mutation("source_coverage_gap_rejected", lambda p: [t.update(requirement_ids=[]) for t in p["tasks"]])
            missing_contract = "oracle-unregistered"
            while any(c["contract_id"] == missing_contract for c in authority["contracts"]):
                missing_contract += "-x"
            mutation("unregistered_contract_pin_rejected", lambda p: p["tasks"][0].update(contract_consumes=[{
                "contract_id": missing_contract, "version": 1, "spec_sha256": "0" * 64}]))
        else:
            result["original_source_meaning_preserved"] = True
            result["exact_write_scope_and_owner_bound"] = True
            for name, data, key in (("request_byte_tamper_rejected", request_raw, "FORGEFLOW_DRAFT_REQUEST_SHA256"),
                                   ("authority_byte_tamper_rejected", authority_raw, "FORGEFLOW_PLANNING_AUTHORITY_SHA256"),
                                   ("source_byte_tamper_rejected", source_raw, "FORGEFLOW_PLANNING_SOURCE_SHA256")):
                result[name] = rejects(lambda d=data, k=key: decode_pinned(d + b" ", env[k], name))
            mutation("authority_field_injection_rejected", lambda p: p["tasks"][0].update(owner_id="oracle-other-owner"))
            outside = "oracle-outside/result.txt"
            while any(covers(scope, outside) for scope in request["write_set"]):
                outside = "x-" + outside
            mutation("expanded_write_scope_rejected", lambda p: p["tasks"][0].update(write_set=[outside]))
            mutation("zero_case_denominator_rejected", lambda p: p["tasks"][0].update(verification_case_count=0))
            mutation("invalid_resource_vector_rejected", lambda p: p["tasks"][0]["resource_request"].update(active_slot=True))
            limit = authority["resources"]["effective_limits"]["active_slot"]
            mutation("resource_cap_expansion_rejected", lambda p: p["tasks"][0]["resource_request"].update(active_slot=limit + 1))
            mutation("invented_known_input_hash_rejected", lambda p: p["tasks"][0].update(inputs=[{
                "path": authority["source_input"]["path"], "sha256": "0" * 64, "producer_task_id": None}]))
            result["strict_duplicate_keys_rejected"] = rejects(lambda: strict_load('{"tasks":[],"tasks":[{}]}'))
            result["truncated_json_rejected"] = rejects(lambda: strict_load('{"schema_version":"' + SCHEMA + '","tasks":['))
            mutation("unknown_fields_rejected", lambda p: p.update(unsupported=True))
            mutation("protocol_version_mismatch_rejected", lambda p: p.update(schema_version="forgeflow.planning-intent.v999"))
            stale = dict(binding, context_hash="0" * 64 if binding["context_hash"] != "0" * 64 else "1" * 64)
            result["stale_context_binding_rejected"] = rejects(lambda: validate_binding(stale, env, request, authority))
            mismatch = copy.deepcopy(authority)
            mismatch["current_inputs"][authority["source_input"]["path"]] = "0" * 64
            if mismatch["current_inputs"][authority["source_input"]["path"]] == authority["source_input"]["sha256"]:
                mismatch["current_inputs"][authority["source_input"]["path"]] = "1" * 64
            result["source_input_snapshot_mismatch_rejected"] = rejects(lambda: validate(intent, request, mismatch, source))
    except Exception as exc:
        errors.append(type(exc).__name__ + ": " + str(exc))
    return result, errors


def main():
    env = os.environ
    role = env["FORGEFLOW_VERIFICATION_ROLE"]
    binding = strict_load(env["FORGEFLOW_EVIDENCE_BINDING"])
    result = {name: False for name, _ in CASES[role]}
    errors = []
    try:
        raw = Path(env["FORGEFLOW_ARTIFACT_PATH"]).read_bytes()
        request_raw = Path(env["FORGEFLOW_DRAFT_REQUEST_PATH"]).read_bytes()
        authority_raw = Path(env["FORGEFLOW_PLANNING_AUTHORITY_PATH"]).read_bytes()
        source_raw = Path(env["FORGEFLOW_PLANNING_SOURCE_PATH"]).read_bytes()
        result, errors = run_cases(role, raw, request_raw, authority_raw, source_raw, env, binding)
    except Exception as exc:
        errors.append(type(exc).__name__ + ": " + str(exc))
    report = {"binding": binding, "oracle_id": ORACLE,
              "cases": [{"name": name, "kind": kind, "outcome": "passed" if result[name] else "failed"}
                        for name, kind in CASES[role]]}
    report_path = Path(env["FORGEFLOW_REPORT_PATH"])
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"role": role, "executed": len(result), "failed": sum(not v for v in result.values()), "errors": errors}))
    return 0 if all(result.values()) and not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
