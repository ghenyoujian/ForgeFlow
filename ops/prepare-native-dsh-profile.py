#!/usr/bin/env python3
"""Plan native role allocation from one verified immutable shared DSH profile.

This filesystem-only planner never registers profiles, starts Workers, calls
models, runs Doctors or changes delivery-config. All frozen project role positions map
to one existing full profile and proposed per-attempt root bindings. Shared
runtime content and SDK inventory are verified once, without per-role copies.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

SCHEMA = "forgeflow.native-role-profile-factory.v1"
ROUTE = "newapi/glm-5.3-max.v1"
DUMMY = {"version": 1, "refs": {"FORGEFLOW_MODEL_RELAY_DUMMY": "forgeflow-relay-no-provider-secret"}}


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_root(path):
    path = Path(path).resolve()
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.stat().st_mode & 0o077 or str(path).startswith("/mnt/"):
        raise ValueError("factory output must be a private Linux directory (0700)")
    return path


def write(path, raw, mode=0o400):
    path = Path(path)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def json_write(path, value):
    write(path, encoded(value))


class SharedBase:
    def __init__(self, config_path, resource_receipt):
        self.config_path = Path(config_path).resolve(strict=True)
        self.config = load(self.config_path)
        self.profile = self.config["profile"]
        self.managed = self.config["managed_dsh"]
        self.pins = {}
        for pin in self.profile["artifact_pins"]:
            path = Path(pin["path"]).resolve(strict=True)
            if digest(path.read_bytes()) != pin["sha256"]:
                raise ValueError("shared native pin changed: " + str(path))
            if str(path) in self.pins:
                raise ValueError("duplicate resolved native pin: " + str(path))
            self.pins[str(path)] = pin["sha256"]
        self.doctor_path = Path(self.managed["doctor"]).resolve(strict=True)
        self.doctor = load(self.doctor_path)
        if (self.doctor["executor_profile_id"] != self.profile["id"]
                or self.doctor["mode_id"] != self.managed["mode_id"]
                or self.doctor["exit_code"] != 0):
            raise ValueError("shared Doctor does not match the actual base profile")
        for path, sha in self.pins.items():
            if path != str(self.doctor_path) and self.doctor["artifact_sha256"].get(path) != sha:
                raise ValueError("shared Doctor pin inventory differs: " + path)
        if load(self.managed["credentials"]) != DUMMY:
            raise ValueError("role factory requires provider-free dummy credentials")
        self.mode = load(self.managed["mode_manifest"])
        if self.mode["schema_version"] != "forgeflow.dsh-mode.v3":
            raise ValueError("full native role factory requires v3")
        mode_dir = Path(self.managed["mode_manifest"]).parent
        self.roles_document = load(mode_dir / "agent-roles.json")
        self.roles = self.roles_document["roster"]
        if (not 1 <= len(self.roles) <= 10000 or self.roles_document.get("positions") != len(self.roles)
                or len({r["position_id"] for r in self.roles}) != len(self.roles)):
            raise ValueError("a nonempty exact project-sized frozen roster is required")
        self.rows = load(self.managed["preset_patch"])
        bindings = [entry for row in self.rows for entry in row.get("insert", [])
                    if entry.get("id") == "forgeflow-team-binding"]
        if len(bindings) != 1:
            raise ValueError("full native role binding must occur exactly once")
        self.base_position = bindings[0]["config"]["default_root_position_id"]
        self.selected = load(self.managed["selected_model_config"])
        default = next(row["config"] for row in self.selected if row["id"] == "agent-default-model")
        provider = next(row["config"]["providers"]["newapi"] for row in self.selected if row["id"] == "llm-pi-ai")
        model = provider["models"]
        if (default != {"provider": "newapi", "model": "glm-5.3", "reasoningEffort": "max"}
                or len(model) != 1 or model[0]["id"] != "glm-5.3"
                or model[0]["input"] != ["text"] or model[0]["contextWindow"] != 1000000
                or model[0]["maxTokens"] != 131072 or provider["compat"]["forceAdaptiveThinking"] is not True
                or self.profile["model_route_id"] != ROUTE
                or self.managed["model_relay"]["response_idle_timeout_ms"] != 300000):
            raise ValueError("shared base must freeze the exact full GLM Max/1M/300-second policy")
        closure_fact = self.doctor["sdk_runtime_closure"]
        self.closure_path = Path(closure_fact["manifest_path"]).resolve(strict=True)
        self.closure = load(self.closure_path)
        if self.pins.get(str(self.closure_path)) != closure_fact["manifest_sha256"]:
            raise ValueError("shared SDK inventory is outside the verified native pins")
        if self.closure["schema_version"] != "forgeflow.installed-runtime-closure.v1":
            raise ValueError("unsupported shared SDK inventory")
        for key in ("seed_package", "resolution", "package_count", "file_count", "total_bytes", "missing_optional_dependencies"):
            if self.closure[key] != closure_fact[key]:
                raise ValueError("shared SDK receipt differs: " + key)
        if len(self.closure["packages"]) != self.closure["package_count"] or len(self.closure["files"]) != self.closure["file_count"]:
            raise ValueError("shared SDK denominator differs")
        runtime_root = Path(self.doctor["runtime_package"]).resolve().parents[2]
        seed = runtime_root / "packages/llm/llm-pi-ai/node_modules/@earendil-works/pi-ai"
        if str(seed.resolve(strict=True)) != self.closure["seed_package"]:
            raise ValueError("installed SDK seed resolution changed")
        for edge in self.closure["dependency_edges"]:
            package = Path(edge["from"])
            resolved = None
            for ancestor in (package, *package.parents):
                candidate = ancestor / "node_modules" / edge["dependency"]
                if (candidate / "package.json").is_file():
                    resolved = str(candidate.resolve())
                    break
            if resolved != edge["resolved"]:
                raise ValueError("installed SDK dependency resolution changed: " + edge["dependency"])
        for path, fact in self.closure["files"].items():
            if self.pins.get(path) != fact["sha256"]:
                raise ValueError("SDK content is outside the shared verified pins: " + path)
        receipt = load(resource_receipt)
        self.resource = receipt.get("registration", receipt).get("data", receipt)
        if self.resource["sandbox"] != self.config["sandbox"]:
            raise ValueError("actual canonical resource sandbox differs from the base Worker configuration")
        self.resource_receipt_path = str(Path(resource_receipt).resolve())
        self.base_digest = digest(encoded({"profile": self.profile, "native_mode": self.managed}))

    def resource_for(self, identity, sandbox):
        result = copy.deepcopy(self.resource)
        result.pop("revision", None)
        result.update(id=identity, sandbox=copy.deepcopy(sandbox))
        return result

    def audit_existing(self, path, expected_position):
        path = Path(path)
        if not path.is_file():
            return {"state": "MISSING", "config_path": str(path)}
        config = load(path)
        profile, managed = config["profile"], config["managed_dsh"]
        privately_verified, shared_verified = 0, 0
        for pin in profile["artifact_pins"]:
            actual = str(Path(pin["path"]).resolve(strict=True))
            if self.pins.get(actual) == pin["sha256"]:
                shared_verified += 1
            else:
                if digest(Path(actual).read_bytes()) != pin["sha256"]:
                    raise ValueError("existing role private pin changed: " + actual)
                privately_verified += 1
        rows = load(managed["preset_patch"])
        position = next(entry["config"]["default_root_position_id"]
                        for row in rows for entry in row.get("insert", [])
                        if entry.get("id") == "forgeflow-team-binding")
        if position != expected_position:
            raise ValueError("existing role profile selects another root position")
        doctor = load(managed["doctor"])
        if doctor["exit_code"] != 0 or doctor["executor_profile_id"] != profile["id"]:
            raise ValueError("existing role profile Doctor identity differs")
        for pin in profile["artifact_pins"]:
            actual = str(Path(pin["path"]).resolve())
            if actual != str(Path(managed["doctor"]).resolve()) and doctor["artifact_sha256"].get(actual) != pin["sha256"]:
                raise ValueError("existing role Doctor inventory differs from the frozen profile")
        if load(managed["credentials"]) != DUMMY:
            raise ValueError("existing role credential source is not provider-free")
        registration = dict(profile, kind="DSH_MANAGED", native_mode=managed)
        resource = self.resource_for("native-existing-" + expected_position.lower() + "-v1", config["sandbox"])
        return {"state": "FILESYSTEM_VERIFIED_NOT_REGISTERED_OR_RUNTIME_QUALIFIED",
                "config_path": str(path.resolve()), "executor_profile_id": profile["id"],
                "root_position_id": position, "shared_pins_reused": shared_verified,
                "private_pins_verified": privately_verified,
                "registration_value": registration, "resource_value": resource,
                "sandbox_matches_v12_resource": config["sandbox"] == self.resource["sandbox"],
                "resource_sandbox_matches_worker": resource["sandbox"] == config["sandbox"],
                "model_route_id": profile["model_route_id"],
                "idle_timeout_ms": managed["model_relay"]["response_idle_timeout_ms"],
                "blockers": ["FRESH_SCOPED_WORKER_IDENTITY_REQUIRED", "ACTUAL_API_REGISTRATION_NOT_OBSERVED",
                             "ROLE_RESOURCE_PROFILE_AND_ENVELOPE_REVIEW_REQUIRED", "NATIVE_BUSINESS_ACCEPTANCE_NOT_OBSERVED"]}


def plan(base, output, legacy_root=None):
    catalog_path = Path(base.managed["mode_manifest"]).parent / "agent-roles.json"
    catalog_sha = digest(catalog_path.read_bytes())
    registration_path = output / "shared-registration-value.json"
    resource_path = output / "shared-resource-value.json"
    registration = dict(base.profile, kind="DSH_MANAGED", native_mode=base.managed)
    resource = copy.deepcopy(base.resource)
    rows = []
    for role in base.roles:
        position = role["position_id"]
        rows.append({
            "position_id": position, "role_id": position, "owner_id": role["owner_id"],
            "team_id": role["owner_team_id"], "preset_id": role["preset_id"],
            "role": role["role"], "specialty": role["specialty"],
            "parent_role_id": role["organizational_parent_position_id"],
            "executor_profile_id": base.profile["id"],
            "worker_config": str(base.config_path),
            "registration_value": str(registration_path),
            "resource_value": str(resource_path),
            "resource_profile_id": base.resource["id"],
            "state": "PLANNED_ROLE_BINDING_NOT_GRANTED", "actual_worker_id": None,
            "runtime_pid": None, "native_session_id": None,
            "native_runtime_qualified": False,
            "proposed_execution_binding_template": {
                "schema_version": "forgeflow.native-root-binding.v1",
                "project_id": base.config["project_id"], "task_id": None, "task_revision": None,
                "input_digest": None, "planning_card_id": None,
                "owner_id": role["owner_id"], "team_id": role["owner_team_id"],
                "position_id": position, "preset_id": role["preset_id"],
                "catalog_sha256": catalog_sha,
            },
            "required_task_semantic_anchors": ["forgeflow:native-root:v1:" + position + ":" + catalog_sha],
            "auxiliary_card_anchor_template": "forgeflow:native-root-planning-card:<actual_target_card_id>",
            "resource_scopes": base.config.get("role_resource_scopes", {}).get(position, []),
            "blockers": ["AUTHORITATIVE_PER_ATTEMPT_ROLE_BINDING_REQUIRED",
                         "PINNED_IMPORTED_ROLE_POLICY_REQUIRED",
                         "TASK_OWNER_TEAM_AND_ROLE_SEMANTIC_REVIEW_REQUIRED",
                         "REVIEWED_EXECUTION_ENVELOPE_AND_HOST_CAPACITY_REQUIRED",
                         "ACTUAL_NATIVE_ROLE_AND_BUSINESS_ACCEPTANCE_NOT_OBSERVED"],
        })
    audits = {}
    if legacy_root:
        raise ValueError("legacy audits belong to an explicit external project adapter")
    manifest = {
        "schema_version": SCHEMA, "project_id": base.config["project_id"],
        "state": "PLAN_ONLY_NOT_RUNTIME_READY", "positions": len(base.roles),
        "minimum_actual_concurrent_agents_target": base.config.get("concurrency_target"), "logical_concurrency_cap": None,
        "model": {"provider": "newapi", "model": "glm-5.3", "display": "GLM5.3 Max",
                  "route_id": ROUTE, "reasoning_effort": "max", "context_window": 1000000,
                  "max_output_tokens": 131072, "input": ["text"], "idle_timeout_ms": 300000},
        "base_config": str(base.config_path), "base_config_sha256": digest(base.config_path.read_bytes()),
        "base_profile_id": base.profile["id"], "base_profile_binding_sha256": base.base_digest,
        "canonical_resource_receipt": base.resource_receipt_path,
        "canonical_resource_id": base.resource["id"],
        "shared_pins": {"count": len(base.pins), "verified_once_in_this_batch": True,
                        "inventory_path": str(output / "shared-pins.json"),
                        "sdk_manifest_path": str(base.closure_path),
                        "sdk_package_count": base.closure["package_count"],
                        "sdk_file_count": base.closure["file_count"],
                        "sdk_total_bytes": base.closure["total_bytes"]},
        "resource_template": base.resource,
        "shared_worker_topology": {
            "proposal": "ONE_SHARED_WORKER_ONE_IMMUTABLE_FULL_PROFILE",
            "executor_profile_id": base.profile["id"], "resource_profile_id": base.resource["id"],
            "observed_worker_template_id": base.config["worker_id"],
            "observed_worker_max_active_attempts": base.config["max_active_attempts"],
            "desired_worker_max_active_attempts": 20,
            "concurrency_target": "At least 20 actual concurrent admitted native agents; capacity set after host and ancestor-policy review",
            "per_attempt_isolation": ["Unique attempt UUID", "Independent delegated process root",
                                      "Private native home and preset patch", "Canonical Owner/team/position binding"],
            "native_root_binding_contract_status": "AGREED_CANONICAL_V1_SCHEMA_PENDING_ACTUAL_ADMISSION",
            "required_pinned_mode_policy": "IMPORTED_PLANNING_ROLE_V1",
            "observed_pinned_mode_policy": base.mode.get("native_root_binding_policy"),
            "binding_location": "execution_bindings.native_root_binding",
            "worker_mutates_shared_preset": False,
            "resource_sandbox_matches_worker": base.resource["sandbox"] == base.config["sandbox"],
            "canonical_data_root": base.config["data_root"],
            "hardware_ready": None, "actual_concurrency_qualified": None,
        },
        "roles": rows, "existing_profiles_review": audits,
        "source_profiles_unchanged": True, "actual_workers_started": 0, "model_calls": 0,
        "notes": ["Unchanged installed files, SDK inventory, selected model, policy and native modules remain shared",
                  "One shared profile/registration/SDK inventory serves every position; no per-position runtime duplication",
                  "Proposed binding templates contain no Task identity and are not admitted immutable Attempt bindings",
                  "Worker derives a private role preset patch only from the authoritative per-attempt binding",
                  "Copied CPU/memory/pids/child-policy settings are source facts and do not prove 20-agent host readiness",
                  "Worker identity and credentials are assigned by the controller; canonical data_root stays shared",
                  "Resource sandbox must equal that role's Worker sandbox before any admission"],
    }
    json_write(registration_path, registration)
    json_write(resource_path, resource)
    json_write(output / "shared-pins.json", {"schema_version": SCHEMA, "pins": base.pins})
    json_write(output / "role-factory-manifest.json", manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan",))
    parser.add_argument("--base-config", required=True, type=Path)
    parser.add_argument("--resource-receipt", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--legacy-root", type=Path)
    args = parser.parse_args()
    try:
        output = private_root(args.output)
        base = SharedBase(args.base_config, args.resource_receipt)
        manifest = plan(base, output, args.legacy_root)
        result = {"result": manifest["state"], "roles": len(manifest["roles"]),
                  "shared_pins_verified_once": len(base.pins),
                  "manifest": str(output / "role-factory-manifest.json"),
                  "doctors_started": 0, "models_started": 0, "workers_started": 0}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(json.dumps({"result": "BLOCKED", "message": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
