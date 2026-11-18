#!/usr/bin/env python3
"""Materialize Owner-reviewed native presets into a new immutable DSH profile.

Invoked only by the authenticated configuration API. No model calls, active home
writes, native session creation, financial settlement or product credit occur.
"""
import argparse
import copy
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import uuid
import traceback
from urllib.parse import unquote, urlparse
import yaml

EDIT_KEYS = {"maxConcurrentAgents", "maxTotalAgents", "maxMembers", "maxTasks",
             "maxPendingMessagesPerMember", "maxMessageBytes", "maxDepth",
             "enableRunInBackground", "backgroundMode"}
REQUIRED = {"subagent", "subagent-spawn-in-process", "subagent-fork-in-process",
            "tool-subagent", "tool-subagent-fork", "workflow-ptc", "tool-workflow",
            "agent-team", "tool-agent-team", "tool-plugin-manager"}


class Invalid(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = "NATIVE_CONFIGURATION_" + code


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def write(path, value, mode=0o600):
    raw = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).encode() + b"\n"
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    with os.fdopen(os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode), "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise Invalid("IDENTITY_INVALID")


def checked_worker_capacity(value):
    # bool is an int subclass in Python; configuration capacities are integers.
    if type(value) is not int or not 1 <= value <= 64:
        raise Invalid("WORKER_CAPACITY_INVALID")
    return value


def current_worker_capacity(cfg, profile_id):
    templates = [worker for worker in cfg["workers"]
                 if worker.get("executor_profile_id", cfg["executor_profile_id"]) == profile_id][:2]
    if not templates:
        raise Invalid("WORKER_TEMPLATE_UNAVAILABLE")
    capacities = []
    for worker in templates:
        actual, _ = private_json(worker["config"])
        capacity = checked_worker_capacity(actual.get("max_active_attempts"))
        if worker.get("max_active_attempts", capacity) != capacity:
            raise Invalid("WORKER_CAPACITY_BINDING_CHANGED")
        capacities.append(capacity)
    # For a historical heterogeneous pair, show the lower existing ceiling.
    # Old four-field drafts still retain each Worker's individual value.
    return min(capacities)


def resource_document(value):
    if not isinstance(value,dict):raise Invalid("RESOURCE_PROFILE_MISSING")
    value = copy.deepcopy(value);value.pop("revision",None)
    identifier(value.get("id"))
    sandbox = value.get("sandbox")
    if (not isinstance(sandbox,dict) or sandbox.get("network_allowed") is not False
            or not isinstance(sandbox.get("readonly_paths"),list)
            or not sandbox["readonly_paths"]
            or any(not isinstance(path,str) or not Path(path).is_absolute() for path in sandbox["readonly_paths"])):
        raise Invalid("RESOURCE_SANDBOX_INVALID")
    return value


def inherit_empty_plugin_configs(rows):
    """An empty patch config replaces required bundle defaults in Cordis.

    The editor exposes selected keys, not permission to erase the rest of a
    plugin's official configuration. Restore omitted-config inheritance for
    historic drafts that materialized an unedited empty object.
    """
    for row in rows:
        if not isinstance(row,dict):continue
        if row.get("config") == {}:row.pop("config")
        inherit_empty_plugin_configs(row.get("insert",[]))
        config = row.get("config",{})
        if isinstance(config,dict):inherit_empty_plugin_configs(config.get("plugins",[]))


def runtime_resource_profile(input, native, rows, root):
    """Preserve reviewed resource constraints and mount pinned runtime leaves."""
    resource = resource_document(input.get("base_resource_profile"))
    resource["id"] = native["id"] + "-resources"
    identifier(resource["id"])
    pins = {pin["path"] for pin in native["artifact_pins"]}
    required = set()
    def require_file(value):
        path = Path(value)
        if (not path.is_absolute() or str(path) not in pins
                or path.is_symlink() or not path.is_file()):
            raise Invalid("RUNTIME_MOUNT_PIN_MISSING")
        required.add(str(path))
    def walk(value):
        if isinstance(value,list):
            for item in value:walk(item)
        elif isinstance(value,dict):
            module = value.get("name")
            if isinstance(module,str) and module.startswith("file:"):
                parsed = urlparse(module)
                if parsed.netloc not in {"","localhost"} or parsed.query or parsed.fragment:
                    raise Invalid("RUNTIME_MODULE_URI_INVALID")
                require_file(unquote(parsed.path))
            config = value.get("config",{})
            if isinstance(config,dict):
                for key in ("module_anchor","launcher","ioctl_guard"):
                    if key in config:require_file(config[key])
                walk(config.get("plugins",[]))
            walk(value.get("insert",[]))
    walk(rows)
    # Include pinned siblings used by module-relative imports and the managed
    # bridge/transport. Never mount the publication root, credentials or homes.
    for name in ("bundle","helpers"):
        directory = root/name
        if not directory.exists():continue
        for path in directory.rglob("*"):
            if (path.is_file() and (path.suffix in {".mjs",".cjs",".js"}
                                   or name == "helpers" and path.stat().st_mode & 0o111)):
                require_file(str(path))
    readonly = list(resource["sandbox"]["readonly_paths"])
    for path in sorted(required):
        if not any(Path(path) == Path(base) or Path(path).is_relative_to(Path(base)) for base in readonly):
            readonly.append(path)
    resource["sandbox"]["readonly_paths"] = sorted(set(readonly))
    return resource, sorted(required)


def trusted_module(name):
    path = Path(__file__).with_name(name)
    if not path.exists():
        path = Path(__file__).resolve().parents[1]/"crates/executors/presets/forgeflow"/name
    if path.is_symlink() or not path.is_file():raise Invalid("PUBLISHER_MODULE_MISSING")
    return path


def load(input):
    profile = input["base_profile"]
    cfg_path = Path(input["config_path"])
    if cfg_path.is_symlink() or cfg_path.stat().st_mode & 0o077:
        raise Invalid("PRIVATE_SOURCE_INVALID")
    raw = cfg_path.read_bytes()
    if sha(raw) != input["base_config_sha256"]:
        raise Invalid("SOURCE_STALE")
    cfg = json.loads(raw)
    resource_document(input.get("base_resource_profile"))
    if cfg["project_id"] != input["project_id"] or cfg["expected_provider_model_id"] != "glm-5.3":
        raise Invalid("MODEL_POLICY_INVALID")
    pins = {row["path"]: row["sha256"] for row in profile["artifact_pins"]}
    patch_path = Path(profile["native_mode"]["preset_patch"])
    roster_path = patch_path.parent / "agent-roles.json"
    def pinned(path):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
            raise Invalid("PIN_INVALID")
        raw = path.read_bytes()
        if pins.get(str(path)) != sha(raw):
            raise Invalid("PIN_CHANGED")
        return json.loads(raw)
    rows, roster = pinned(patch_path), pinned(roster_path)
    presets, plugins, native = [], [], {}
    for row in rows:
        for entry in ([row] if row.get("id") else row.get("insert", [])):
            entry_id = entry.get("id")
            if not entry_id:
                continue
            native[entry_id] = entry
            if entry.get("name") == "@deepseek-ai/dsh-agent-preset":
                definition = entry["config"]
                persona = next((r for r in definition["plugins"] if r.get("name") == "@deepseek-ai/dsh-persona"), None)
                if not persona:
                    raise Invalid("PERSONA_UNAVAILABLE")
                presets.append({"id":definition["id"], "name":definition.get("name",definition["id"]),
                                "description":definition.get("description",""),
                                "persona_prefix":persona.get("config",{}).get("prefix",""),
                                "clone_from":definition["id"]})
            elif entry_id not in {"agent-default-model", "agent-preset-registry", "fs-sandbox", "sandbox"} and not entry_id.startswith("forgeflow-"):
                editable = {k:v for k,v in entry.get("config",{}).items() if k in EDIT_KEYS}
                plugins.append({"entry_id":entry_id, "enabled":entry.get("disabled") is not True,
                                "config":editable})
    spec = {"base_executor_profile_id":profile["id"], "presets":presets, "plugins":plugins,
            "role_bindings":[{"position_id":r["position_id"],"preset_id":r["preset_id"]} for r in roster["roster"]],
            "max_active_attempts_per_worker":current_worker_capacity(cfg, profile["id"])}
    return cfg, profile, patch_path, rows, roster, native, spec


def validate(input, baseline):
    _, profile, _, _, _, native, source = baseline
    draft = input["draft"]
    if draft["base_config_sha256"] != input["base_config_sha256"]:
        raise Invalid("SOURCE_STALE")
    spec = draft["spec"]
    required = {"base_executor_profile_id", "presets", "plugins", "role_bindings"}
    if (not isinstance(spec, dict) or not required <= set(spec)
            or set(spec) - required - {"max_active_attempts_per_worker"}
            or spec["base_executor_profile_id"] != profile["id"] or len(canonical(spec)) > 4 * 1024 * 1024):
        raise Invalid("SPEC_INVALID")
    if "max_active_attempts_per_worker" in spec:
        checked_worker_capacity(spec["max_active_attempts_per_worker"])
    templates = {r["id"]:r for r in source["presets"]}
    identities = set()
    if not len(templates) <= len(spec["presets"]) <= 1024:
        raise Invalid("PRESET_COUNT_INVALID")
    for row in spec["presets"]:
        if set(row) != {"id","name","description","persona_prefix","clone_from"}:
            raise Invalid("PRESET_FIELDS_INVALID")
        identifier(row["id"])
        if row["id"] in identities or row["clone_from"] not in templates:
            raise Invalid("PRESET_TEMPLATE_INVALID")
        identities.add(row["id"])
        for key,maximum in [("name",256),("description",4096),("persona_prefix",32768)]:
            if not isinstance(row[key],str) or not row[key].strip() and key != "description" or len(row[key].encode()) > maximum:
                raise Invalid("PRESET_TEXT_INVALID")
        # Editing a current definition must retain its own composition template.
        if row["id"] in templates and row["clone_from"] != row["id"]:
            raise Invalid("EXISTING_PRESET_TEMPLATE_CHANGED")
    if not set(templates) <= identities:
        raise Invalid("ORIGINAL_PRESETS_REMOVED")
    plugin_sources = {r["entry_id"]:r for r in source["plugins"]}
    seen = set()
    for row in spec["plugins"]:
        if set(row) != {"entry_id","enabled","config"} or row["entry_id"] not in plugin_sources or row["entry_id"] in seen or type(row["enabled"]) is not bool:
            raise Invalid("PLUGIN_INVALID")
        seen.add(row["entry_id"])
        if row["entry_id"] in REQUIRED and not row["enabled"]:
            raise Invalid("REQUIRED_PLUGIN_DISABLED")
        if not isinstance(row["config"],dict) or set(row["config"]) != set(plugin_sources[row["entry_id"]]["config"]):
            raise Invalid("PLUGIN_CONFIG_FIELDS_INVALID")
        for key,value in row["config"].items():
            old = plugin_sources[row["entry_id"]]["config"][key]
            if type(value) is not type(old):
                raise Invalid("PLUGIN_CONFIG_TYPE_INVALID")
            if type(value) is int and not 1 <= value <= 1000000:
                raise Invalid("PLUGIN_CONFIG_BOUND_INVALID")
            if key == "maxDepth" and value != 2:
                raise Invalid("DESCENDANT_AUTHORITY_CHANGED")
            if key == "backgroundMode" and value not in {"foreground","background","auto","disabled","enabled"} and value != old:
                raise Invalid("PLUGIN_CONFIG_ENUM_INVALID")
    if seen != set(plugin_sources):
        raise Invalid("PLUGIN_SET_CHANGED")
    positions = {r["position_id"] for r in source["role_bindings"]}
    bound = set()
    bound_presets = set()
    for row in spec["role_bindings"]:
        if set(row) != {"position_id","preset_id"} or row["position_id"] not in positions or row["position_id"] in bound or row["preset_id"] not in identities or row["preset_id"] in bound_presets:
            raise Invalid("ROLE_BINDING_INVALID")
        bound.add(row["position_id"])
        bound_presets.add(row["preset_id"])
    if bound != positions:
        raise Invalid("ORIGINAL_POSITIONS_REMOVED")
    return spec


def materialize(input, baseline, spec):
    cfg = baseline[0]
    locks = Path(cfg["state_dir"])/"native-configuration-publications"
    locks.mkdir(mode=0o700,parents=True,exist_ok=True)
    identifier(input["draft"]["draft_id"])
    lock_path = locks/(input["draft"]["draft_id"] + ".lock")
    with os.fdopen(os.open(lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600),"r+") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        return materialize_locked(input,baseline,spec)


def materialize_locked(input, baseline, spec):
    cfg, original, patch_path, source_rows, source_roster, _, _ = baseline
    draft = input["draft"]
    identifier(draft["draft_id"])
    spec_sha = sha(canonical(spec))
    if draft.get("spec_sha256") != spec_sha:
        raise Invalid("SPEC_HASH_CHANGED")
    profile_id = "native-config-" + draft["draft_id"][:40] + "-" + spec_sha[:12]
    original_root = patch_path.parent.parent
    root = Path(cfg["state_dir"]) / "native-configuration-publications" / profile_id
    root.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if root.is_symlink():
        raise Invalid("PUBLICATION_PATH_INVALID")
    manifest_path = root / "publication.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if manifest["spec_sha256"] != spec_sha or manifest["base_config_sha256"] != input["base_config_sha256"]:
            raise Invalid("PUBLICATION_CONFLICT")
        if ("resource_profile" not in manifest or manifest.get("base_resource_profile_sha256")
                != sha(canonical(resource_document(input.get("base_resource_profile"))))):
            raise Invalid("PUBLICATION_REBUILD_REQUIRED")
        for pin in manifest["profile"]["artifact_pins"]:
            if sha(Path(pin["path"]).read_bytes()) != pin["sha256"]:
                raise Invalid("PUBLICATION_PIN_CHANGED")
        return manifest
    if root.exists():
        # Failed previews are retained; a separate retry folder owns new work.
        retained = root.with_name(root.name + ".failed-" + uuid.uuid4().hex)
        root.rename(retained)
    root.mkdir(mode=0o700)
    for directory in ["bundle","doctor-home","credentials"]:
        source = original_root / directory
        if source.exists():
            if any(x.is_symlink() for x in source.rglob("*")):
                raise Invalid("SOURCE_SYMLINK")
            shutil.copytree(source, root / directory)
    # Copy other source artifacts only when their original identity is pinned.
    for pin in original["artifact_pins"]:
        source = Path(pin["path"])
        if source.is_relative_to(original_root):
            if source.is_symlink() or sha(source.read_bytes()) != pin["sha256"]:
                raise Invalid("PIN_CHANGED")
            destination = root/source.relative_to(original_root)
            destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            if not destination.exists():shutil.copyfile(source,destination)
    def relocate(value):
        if isinstance(value,str):return value.replace(str(original_root),str(root))
        if isinstance(value,list):return [relocate(v) for v in value]
        if isinstance(value,dict):return {relocate(k):relocate(v) for k,v in value.items()}
        return value
    # Relocate JSON/YAML configuration references, not source module bytes.
    for path in root.rglob("*"):
        if path.is_dir():path.chmod(0o700);continue
        path.chmod(0o700 if path.stat().st_mode & 0o111 else 0o600)
        if path.suffix in {".json",".yml",".yaml"}:
            raw = path.read_text()
            if str(original_root) in raw:path.write_text(raw.replace(str(original_root),str(root)))
    rows = relocate(copy.deepcopy(source_rows))
    definitions = {}
    for row in rows:
        for entry in row.get("insert",[]):
            if entry.get("name") == "@deepseek-ai/dsh-agent-preset":definitions[entry["config"]["id"]] = entry
    insert = next(row["insert"] for row in rows if any(e.get("name") == "@deepseek-ai/dsh-agent-preset" for e in row.get("insert",[])))
    for edit in spec["presets"]:
        if edit["id"] not in definitions:
            entry = copy.deepcopy(definitions[edit["clone_from"]]);entry["id"] = "preset-" + edit["id"];entry["config"]["id"] = edit["id"];insert.append(entry);definitions[edit["id"]] = entry
        definition = definitions[edit["id"]]["config"]
        definition.update(name=edit["name"],description=edit["description"])
        persona = next(r for r in definition["plugins"] if r.get("name") == "@deepseek-ai/dsh-persona")
        persona.setdefault("config",{})["prefix"] = edit["persona_prefix"]
    edits = {e["entry_id"]:e for e in spec["plugins"]}
    for row in rows:
        for entry in ([row] if row.get("id") else row.get("insert",[])):
            edit = edits.get(entry.get("id"))
            if edit:
                entry["disabled"] = not edit["enabled"]
                if edit["config"]:entry.setdefault("config",{}).update(edit["config"])
    inherit_empty_plugin_configs(rows)
    roster = relocate(copy.deepcopy(source_roster));bindings = {r["position_id"]:r["preset_id"] for r in spec["role_bindings"]}
    for role in roster["roster"]:role["preset_id"] = bindings[role["position_id"]]
    write(root/"bundle/full-preset.json", rows)
    write(root/"bundle/agent-roles.json", roster)
    # The new binder accepts reviewed preset IDs and still enforces unique role,
    # owner/team and fresh-session selection. Existing pinned binders stay frozen.
    for name in ("team-binding.mjs","managed-bridge.mjs"):
        shutil.copyfile(trusted_module(name),root/"bundle"/name)
    for row in rows:
        for entry in row.get("insert",[]):
            if entry.get("id") == "forgeflow-team-binding":
                entry["config"]["bindings"] = copy.deepcopy(roster["roster"])
    write(root/"bundle/full-preset.json",rows)
    native = relocate(copy.deepcopy(original));native.pop("revision",None);native["id"] = profile_id
    resource, runtime_mounts = runtime_resource_profile(input,native,rows,root)
    resource_path = root/"resource-profile.json"
    write(resource_path,resource)
    # Resolve the actual complete profile using the supported CLI surface.
    overlay = root/"doctor-home/profiles/headless/cordis.patch.yml"
    original_overlay = overlay.read_bytes()
    overlay.write_text(yaml.safe_dump(rows,sort_keys=False,allow_unicode=True))
    env = dict(os.environ,DSH_HOME=str(root/"doctor-home"))
    try:
        result = subprocess.run([native["program"],*native["prefix_args"],"--profile",native["profile_name"],"--dump-config"],env=env,capture_output=True,timeout=90)
    finally:
        # The managed Worker injects preset_patch into each fresh attempt. Keep
        # its base home unchanged to avoid mounting the same definitions twice.
        overlay.write_bytes(original_overlay)
    (root/"doctor.stdout").write_bytes(result.stdout);(root/"doctor.stderr").write_bytes(result.stderr)
    if result.returncode or not result.stdout:
        raise Invalid("DOCTOR_FAILED")
    class DumpLoader(yaml.SafeLoader):pass
    DumpLoader.add_constructor("tag:yaml.org,2002:js",lambda loader,node:loader.construct_scalar(node))
    resolved = yaml.load(result.stdout,Loader=DumpLoader)
    def declarations(value):
        if isinstance(value,list):
            for row in value:yield from declarations(row)
        elif isinstance(value,dict):
            if value.get("name") == "@deepseek-ai/dsh-agent-preset":yield value.get("config",{}).get("id")
            for key in ["insert","plugins"]:
                if key in value:yield from declarations(value[key])
    if not {row["id"] for row in spec["presets"]} <= set(declarations(resolved)):
        raise Invalid("RESOLVED_PRESETS_MISSING")
    # Resolution is not a runtime tool qualification. Still reject the known
    # erased-default failure before publishing; the managed bridge separately
    # requires actual root tools/services before its first admitted lifecycle.
    expected_defaults = {"session-query-sqlite":["path"],"plan-mode":["section"],
                         "tool-todo":["allowParallelInProgress"]}
    resolved_by_id = {row.get("id"):row for row in resolved if isinstance(row,dict)}
    for plugin, keys in expected_defaults.items():
        entry = resolved_by_id.get(plugin)
        if entry and entry.get("disabled") is not True and any(key not in entry.get("config",{}) for key in keys):
            raise Invalid("REQUIRED_PLUGIN_DEFAULTS_MISSING")
    # Actual frozen profile pins; original external SDK/program pins stay intact.
    for pin in native["artifact_pins"]:
        path = Path(pin["path"])
        pin["sha256"] = sha(path.read_bytes())
    known = {p["path"] for p in native["artifact_pins"]}
    for path in [overlay,root/"doctor-home/cordis.patch.yml",root/"doctor-home/profiles/headless/cordis.yml",root/"doctor-home/profiles/headless/package.json",resource_path]:
        if str(path) not in known:native["artifact_pins"].append({"path":str(path),"sha256":sha(path.read_bytes())})
    doctor_path = Path(native["native_mode"]["doctor"])
    doctor = json.loads(doctor_path.read_text())
    doctor.update(executor_profile_id=profile_id,exit_code=result.returncode,
                  composition_sha256=sha(result.stdout),raw_composition_path=str(root/"doctor.stdout"),
                  scope="Actual new full native configuration resolution; runtime collaboration and product qualification remain unproven.")
    doctor["artifact_sha256"] = {pin["path"]:pin["sha256"] for pin in native["artifact_pins"] if pin["path"] != str(doctor_path)}
    for key in ["sdk_runtime_closure","native_filesystem_runtime_closure"]:
        receipt = doctor.get(key)
        if receipt and receipt.get("manifest_path"):
            receipt["manifest_sha256"] = sha(Path(receipt["manifest_path"]).read_bytes())
    if isinstance(doctor.get("full_preset"),dict):doctor["full_preset"]["declared"] = len(spec["presets"])
    write(doctor_path,doctor)
    next(pin for pin in native["artifact_pins"] if pin["path"] == str(doctor_path))["sha256"] = sha(doctor_path.read_bytes())
    review = {"schema_version":"forgeflow.native-configuration-review.v1","profile_id":profile_id,
              "spec_sha256":spec_sha,"base_config_sha256":input["base_config_sha256"],
              "preset_count":len(spec["presets"]),"position_count":len(spec["role_bindings"]),
              "native_doctor_exit_code":result.returncode,"native_doctor_sha256":sha(result.stdout),
              "artifact_pins_sha256":sha(canonical(native["artifact_pins"])),
              "resource_profile_id":resource["id"],"resource_profile_sha256":sha(canonical(resource)),
              "runtime_mounts":runtime_mounts,"runtime_tool_availability":"REQUIRES_ACTUAL_CONTROLLED_NATIVE_START",
              "active_profiles_modified":False,"model_calls":0,"runtime_collaboration_qualified":False,
              "original_card_completion_credit":0}
    if "max_active_attempts_per_worker" in spec:
        review["max_active_attempts_per_worker"] = spec["max_active_attempts_per_worker"]
    manifest = {"spec_sha256":spec_sha,"base_config_sha256":input["base_config_sha256"],
                "base_resource_profile_sha256":sha(canonical(resource_document(input["base_resource_profile"]))),
                "profile":native,"resource_profile":resource,"review":review}
    write(manifest_path,manifest)
    for path in root.rglob("*"):
        if path.is_file():path.chmod(0o500 if path.stat().st_mode & 0o111 else 0o400)
    return manifest


def stage_worker_policies(cfg, receipt):
    """Stage reviewed resource limits; START applies them after Worker registration."""
    workers = {worker["worker_id"]: worker for worker in cfg["workers"]}
    ids = receipt["worker_ids"]
    policies = receipt["resource_policies"]
    if not ids or len(set(ids)) != len(ids) or len(policies) != len(ids):
        raise Invalid("WORKER_RESOURCE_IDENTITY_INVALID")
    updates = cfg.setdefault("resource_policy_updates", [])
    if not isinstance(updates, list):raise Invalid("WORKER_RESOURCE_UPDATES_INVALID")
    seen = set();seen_scopes = set();changed = False
    for policy in policies:
        worker_id = policy.get("worker_id");worker = workers.get(worker_id)
        if (worker_id not in ids or worker_id in seen or not worker
                or worker["executor_profile_id"] != receipt["executor_profile_id"]
                or policy["scope_id"] != worker["worker_scope_id"]
                or policy["scope_id"] in seen_scopes or policy.get("revision") != 1
                or policy.get("project_id") is not None or policy.get("team_id") is not None):
            raise Invalid("WORKER_RESOURCE_IDENTITY_INVALID")
        seen.add(worker_id);seen_scopes.add(policy["scope_id"])
        update = {"policy":copy.deepcopy(policy),"expected_revision":None}
        existing = [row for row in updates if row.get("policy",{}).get("scope_id") == policy["scope_id"]]
        if existing:
            if existing != [update]:raise Invalid("WORKER_RESOURCE_UPDATE_CONFLICT")
        else:
            updates.append(update);changed = True
    return changed


def preserve_bytes(path, raw):
    if path.exists():
        if path.read_bytes() != raw:raise Invalid("ACTIVATION_BACKUP_CONFLICT")
        return
    with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"wb") as file:
        file.write(raw);file.flush();os.fsync(file.fileno())


def private_json(path):
    path = Path(path)
    if not path.is_absolute():raise Invalid("PRIVATE_SOURCE_INVALID")
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK),"rb") as file:
        info = os.fstat(file.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1_048_576):
            raise Invalid("PRIVATE_SOURCE_INVALID")
        raw = file.read(1_048_577)
        if len(raw) > 1_048_576:raise Invalid("PRIVATE_SOURCE_INVALID")
    return json.loads(raw), raw


def issue_worker_credentials(cfg, workers, root):
    """Prepare exact scoped grants and private env files; never register a Worker.

    The caller holds its delivery configuration lock and persists modified Worker
    env_file paths. A credential-file lock serializes grants across all projects.
    Existing grants/env files reuse their key, including after interrupted writes.
    """
    runtime, _ = private_json(cfg["runtime_env"])
    credential_path = Path(runtime["FORGEFLOW_WORKER_CREDENTIALS_FILE"])
    if not credential_path.is_absolute():raise Invalid("WORKER_CREDENTIAL_PATH_INVALID")
    root = Path(root);root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if root.is_symlink() or root.stat().st_mode & 0o077:raise Invalid("PRIVATE_SOURCE_INVALID")
    lock_path = credential_path.with_name(credential_path.name+".native-configuration.lock")
    with os.fdopen(os.open(lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600),"r+") as lock:
        info = os.fstat(lock.fileno())
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise Invalid("PRIVATE_SOURCE_INVALID")
        fcntl.flock(lock,fcntl.LOCK_EX)
        credentials, before = private_json(credential_path)
        if (set(credentials) != {"schema_version","workers"}
                or credentials["schema_version"] != "forgeflow.worker-credentials.v1"
                or not isinstance(credentials["workers"],list) or not credentials["workers"]):
            raise Invalid("WORKER_CREDENTIAL_FILE_INVALID")
        by_worker = {};tokens = set()
        reserved = {runtime.get("FORGEFLOW_OWNER_TOKEN"),runtime.get("FORGEFLOW_WORKER_TOKEN")}
        def valid_token(token):
            return (isinstance(token,str) and 24 <= len(token) <= 4096 and token.isascii()
                    and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in token)
                    and token not in reserved)
        def valid_id(value):
            return (isinstance(value,str) and 0 < len(value) <= 256
                    and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value))
        for grant in credentials["workers"]:
            if (not isinstance(grant,dict) or set(grant) != {"worker_id","project_id","token"}
                    or not valid_id(grant["worker_id"]) or not valid_id(grant["project_id"])
                    or not valid_token(grant["token"]) or grant["worker_id"] in by_worker
                    or grant["token"] in tokens):
                raise Invalid("WORKER_CREDENTIAL_FILE_INVALID")
            by_worker[grant["worker_id"]] = grant;tokens.add(grant["token"])
        changed = False;added = False;seen = set()
        for worker in workers:
            worker_id = worker["worker_id"];identifier(worker_id)
            if worker_id in seen:raise Invalid("WORKER_CREDENTIAL_IDENTITY_INVALID")
            seen.add(worker_id)
            grant = by_worker.get(worker_id)
            if grant and grant["project_id"] != cfg["project_id"]:
                raise Invalid("WORKER_CREDENTIAL_SCOPE_CONFLICT")
            env_path = root/(worker_id+".env.json")
            if env_path.exists() or env_path.is_symlink():
                env, _ = private_json(env_path);token = env.get("FORGEFLOW_WORKER_TOKEN")
                if not valid_token(token) or (grant and token != grant["token"]):
                    raise Invalid("WORKER_CREDENTIAL_ENV_CONFLICT")
            else:
                env, _ = private_json(worker["env_file"])
                token = grant["token"] if grant else secrets.token_urlsafe(48)
                while not grant and (token in tokens or not valid_token(token)):
                    token = secrets.token_urlsafe(48)
                env["FORGEFLOW_WORKER_TOKEN"] = token
                for key, value in [("FORGEFLOW_WORKER_ID",worker_id),("FORGEFLOW_WORKER_PROJECT_ID",cfg["project_id"])]:
                    if key in env:env[key] = value
                write(env_path,env)
            if not grant:
                if token in tokens:raise Invalid("WORKER_CREDENTIAL_TOKEN_CONFLICT")
                grant = {"worker_id":worker_id,"project_id":cfg["project_id"],"token":token}
                credentials["workers"].append(grant);by_worker[worker_id] = grant;tokens.add(token);added = True
            if worker["env_file"] != str(env_path):
                worker["env_file"] = str(env_path);changed = True
        if added:
            if len(json.dumps(credentials,ensure_ascii=False,indent=2).encode())+1 > 1_048_576:
                raise Invalid("WORKER_CREDENTIAL_FILE_TOO_LARGE")
            preserve_bytes(credential_path.with_name(credential_path.name+".before-native-"+sha(before)[:16]+".json"),before)
            write(credential_path,credentials)
        return changed


def activate(input):
    """CAS adoption only; a separate protected Native START grants execution."""
    cfg_path = Path(input["config_path"])
    lock_path = cfg_path.with_name("native-configuration.lock")
    with os.fdopen(os.open(lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600),"r+") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        raw = cfg_path.read_bytes();cfg = json.loads(raw);draft = input["draft"]
        if cfg["project_id"] != input["project_id"]:raise Invalid("PROJECT_IDENTITY_INVALID")
        capacity = (checked_worker_capacity(draft["spec"]["max_active_attempts_per_worker"])
                    if "max_active_attempts_per_worker" in draft["spec"] else None)
        resource = resource_document(input.get("published_resource_profile"))
        resource_id = resource["id"];resource_sha = sha(canonical(resource))
        if (draft.get("published_resource_profile_id") != resource_id
                or draft.get("published_resource_profile_sha256") != resource_sha):
            raise Invalid("PUBLISHED_RESOURCE_PROFILE_CHANGED")
        current = cfg.get("native_configuration_activation",{})
        if current.get("draft_id") == draft["draft_id"] and current.get("spec_sha256") == draft["spec_sha256"]:
            path = Path(cfg["state_dir"])/"native-configuration-activations"/draft["draft_id"]/"receipt.json"
            if not path.exists():raise Invalid("ACTIVATION_RECEIPT_UNAVAILABLE")
            receipt_raw = path.read_bytes();receipt = json.loads(receipt_raw)
            if receipt["config_sha256"] != sha(raw):raise Invalid("SOURCE_STALE")
            if (draft["status"] != "PUBLISHED" or receipt["draft_id"] != draft["draft_id"]
                    or receipt["spec_sha256"] != draft["spec_sha256"]
                    or receipt["executor_profile_id"] != draft["published_executor_profile_id"]
                    or receipt.get("project_id",cfg["project_id"]) != cfg["project_id"]
                    or receipt.get("resource_profile_id") != resource_id
                    or receipt.get("resource_profile_sha256") != resource_sha
                    or receipt.get("active_attempts_modified") is not False
                    or receipt.get("execution_rights_granted") is not False):
                raise Invalid("ACTIVATION_RECEIPT_INVALID")
            changed = stage_worker_policies(cfg, receipt)
            workers = [worker for worker in cfg["workers"] if worker["worker_id"] in receipt["worker_ids"]]
            for worker in workers:
                actual = json.loads(Path(worker["config"]).read_text())
                if (worker.get("resource_profile_id") != resource_id
                        or actual.get("sandbox") != resource["sandbox"]):
                    raise Invalid("ACTIVATION_RESOURCE_BINDING_CHANGED")
                if capacity is not None and (worker.get("max_active_attempts") != capacity
                                             or actual.get("max_active_attempts") != capacity):
                    raise Invalid("WORKER_CAPACITY_BINDING_CHANGED")
            changed = issue_worker_credentials(cfg,workers,path.parent) or changed
            if changed or "project_id" not in receipt:
                # Preserve the failed activation exactly before repairing its
                # missing START-time policy declarations. Repeat calls are read-only.
                backup = "before-activation-repair-"+sha(raw)[:16]
                preserve_bytes(path.parent/(backup+"-config.json"),raw)
                preserve_bytes(path.parent/(backup+"-receipt.json"),receipt_raw)
                receipt["project_id"] = cfg["project_id"]
                cfg["native_configuration_activation"]["project_id"] = cfg["project_id"]
                write(cfg_path,cfg)
                receipt["config_sha256"] = sha(cfg_path.read_bytes())
                write(path,receipt)
            return receipt
        if sha(raw) != draft["base_config_sha256"] or sha(raw) != input["base_config_sha256"]:
            raise Invalid("SOURCE_STALE")
        profile = copy.deepcopy(input["published_profile"]);profile.pop("revision",None)
        if draft["status"] != "PUBLISHED" or profile["id"] != draft["published_executor_profile_id"]:
            raise Invalid("NOT_PUBLISHED")
        for pin in profile["artifact_pins"]:
            path = Path(pin["path"])
            if path.is_symlink() or sha(path.read_bytes()) != pin["sha256"]:
                raise Invalid("PUBLICATION_PIN_CHANGED")
        binary = Path(input["worker_binary"])
        if not binary.is_absolute() or binary.is_symlink() or sha(binary.read_bytes()) != input["worker_binary_sha256"]:
            raise Invalid("WORKER_PIN_CHANGED")
        templates = [w for w in cfg["workers"] if w.get("executor_profile_id",cfg["executor_profile_id"]) == draft["spec"]["base_executor_profile_id"]]
        if not templates:raise Invalid("WORKER_TEMPLATE_UNAVAILABLE")
        base_resource = resource_document(input.get("base_resource_profile"))
        if any(worker.get("resource_profile_id",cfg.get("resource_profile_id")) != base_resource["id"] for worker in templates):
            raise Invalid("RESOURCE_PROFILE_VARIANTS_REQUIRE_REVIEW")
        root = Path(cfg["state_dir"])/"native-configuration-activations"/draft["draft_id"]
        root.mkdir(mode=0o700,parents=True,exist_ok=True)
        new_workers = [];new_policies = []
        # Two separate actors retain generator/reviewer independence for new work.
        for index, template in enumerate(templates[:2]):
            worker = copy.deepcopy(template)
            worker_id = "native-config-worker-" + draft["draft_id"][:24] + "-" + draft["spec_sha256"][:12] + "-" + str(index)
            source = Path(template["config"])
            if source.is_symlink() or source.stat().st_mode & 0o077:raise Invalid("PRIVATE_SOURCE_INVALID")
            worker_config = json.loads(source.read_text())
            if capacity is not None:
                worker_config["max_active_attempts"] = capacity
            mode = copy.deepcopy(input["published_profile"]["native_mode"])
            worker_profile = {k:v for k,v in input["published_profile"].items() if k not in {"revision","kind","native_mode"}}
            worker_config.update(worker_id=worker_id,profile=worker_profile,managed_dsh=mode,
                                 data_root=str(root/("worker-state-" + str(index))),
                                 sandbox=copy.deepcopy(resource["sandbox"]))
            config_file = root/("worker-"+str(index)+".json");write(config_file,worker_config)
            worker.update(worker_id=worker_id,config=str(config_file),executor_profile_id=input["published_profile"]["id"],
                          binary=str(binary),binary_sha256=input["worker_binary_sha256"],
                          resource_profile_id=resource_id)
            if capacity is not None:
                worker["max_active_attempts"] = capacity
            policy_sources = {v["scope_id"]:v for v in input["resource_policies"]}
            policy = copy.deepcopy(policy_sources.get(template["worker_scope_id"]))
            if not policy or policy.get("worker_id") != template["worker_id"]:raise Invalid("WORKER_RESOURCE_TEMPLATE_UNAVAILABLE")
            policy.update(scope_id="native-workflow-worker-"+worker_id,worker_id=worker_id,revision=1)
            worker["worker_scope_id"] = policy["scope_id"]
            new_policies.append(policy)
            # The approved global/project resource scopes still enforce capacity.
            new_workers.append(worker)
        profile_id = input["published_profile"]["id"]
        previous_resource_id = cfg["resource_profile_id"]
        # Existing workers must retain the effective resource identity they had
        # before this default changed. An omitted field is not permission to
        # retarget an old executor's sandbox to the newly published profile.
        for existing_worker in cfg["workers"]:
            existing_worker.setdefault("resource_profile_id",previous_resource_id)
        cfg["executor_profile_ids"] = sorted(set(cfg.get("executor_profile_ids",[])) | {cfg["executor_profile_id"],profile_id})
        cfg["executor_profile_id"] = profile_id
        cfg["resource_profile_ids"] = sorted(set(cfg.get("resource_profile_ids",[])) | {cfg["resource_profile_id"],resource_id})
        cfg["resource_profile_id"] = resource_id
        cfg["workers"].extend(new_workers)
        for stage in cfg.get("recipe_publication_policy",{}).get("auto_stages",{}).values():
            if isinstance(stage,dict) and stage.get("executor_profile_id") == draft["spec"]["base_executor_profile_id"]:
                stage["executor_profile_id"] = profile_id
                stage["resource_profile_id"] = resource_id
            elif isinstance(stage,dict) and stage.get("executor_profile_id"):
                stage.setdefault("resource_profile_id",previous_resource_id)
        receipt = {"schema_version":"forgeflow.native-configuration-activation.v1","draft_id":draft["draft_id"],
                   "project_id":cfg["project_id"],
                   "spec_sha256":draft["spec_sha256"],"executor_profile_id":profile_id,
                   "resource_profile_id":resource_id,"resource_profile_sha256":resource_sha,
                   "previous_config_sha256":sha(raw),"worker_ids":[w["worker_id"] for w in new_workers],
                   "active_attempts_modified":False,"execution_rights_granted":False,
                   "model_calls":0,"original_card_completion_credit":0,
                   "effect":"DEFAULT_FOR_FUTURE_BINDING_AFTER_NATIVE_START"}
        cfg["native_configuration_activation"] = copy.deepcopy(receipt)
        receipt["resource_policies"] = new_policies
        stage_worker_policies(cfg,receipt)
        issue_worker_credentials(cfg,new_workers,root)
        # Keep a private exact rollback source and an atomic configuration commit.
        before = root/"before-config.json"
        if not before.exists():
            with os.fdopen(os.open(before,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"wb") as file:file.write(raw)
        write(cfg_path,cfg)
        receipt = copy.deepcopy(receipt);receipt["config_sha256"] = sha(cfg_path.read_bytes())
        write(root/"receipt.json",receipt)
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument("--input",type=Path,required=True);args=parser.parse_args()
    input = json.loads(args.input.read_text());output = Path(input["output_path"])
    try:
        if input["mode"] == "activate":
            write(output,activate(input));return 0
        baseline = load(input)
        if input["mode"] == "context":
            cfg,profile,_,_,_,_,spec = baseline
            value = {"schema_version":"forgeflow.native-configuration-context.v1",
                     "project_id":input["project_id"],"base_config_sha256":input["base_config_sha256"],
                     "spec":spec,"model":"GLM5.3 Max","required_plugins":sorted(REQUIRED),
                     "published_versions_are_immutable":True,"runtime_collaboration_qualified":False}
        else:
            spec = validate(input,baseline)
            if input["mode"] == "validate":value = {"valid":True}
            elif input["mode"] in {"preview","publish"}:
                value = materialize(input,baseline,spec)
                if input["mode"] == "publish" and input["draft"].get("review") != value["review"]:
                    raise Invalid("REVIEW_CHANGED")
            else:raise Invalid("ACTION_INVALID")
        write(output,value)
        return 0
    except Exception as error:
        write(output,{"error":{"code":error.code if isinstance(error,Invalid) else "NATIVE_CONFIGURATION_PREVIEW_FAILED"},
                      "private_error_sha256":sha(str(error).encode()),"active_profiles_modified":False})
        # Full diagnostics remain private; never emit provider credentials.
        diagnostic = output.with_suffix(".private-error.txt")
        with os.fdopen(os.open(diagnostic,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"w") as file:file.write(traceback.format_exc())
        return 1


if __name__ == "__main__":sys.exit(main())
