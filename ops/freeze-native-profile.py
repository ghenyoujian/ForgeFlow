#!/usr/bin/env python3
"""Freeze an installed npm DSH runtime and project pack, using actual zero-model Doctor.

No legacy source checkout, personal DSH home, credentials or running session is
read or modified. Runtime files are referenced and hashed, not copied per role.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
PRESET = ROOT / "crates/executors/presets/forgeflow"
if not PRESET.is_dir(): PRESET = ROOT / "executors/presets/forgeflow"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


C = module("freeze_campaign", Path(__file__).with_name("concurrency-readiness.py"))
N = module("runtime_closure", Path(__file__).with_name("native-runtime-closure.py"))


def freeze(a):
    modules = a.node_modules.resolve(strict=True)
    package = modules / "@deepseek-ai/dsh/package.json"
    runtime = C.read_json(package)
    C.require(runtime["name"] == "@deepseek-ai/dsh", "installed official DSH package required")
    node = a.node.resolve(strict=True)
    entry = package.parent / runtime["bin"]["dsh"]
    pack = a.project_pack.resolve(strict=True)
    manifest = C.read_json(pack / "manifest.json")
    C.require(manifest["schema_version"] == "forgeflow.project-pack.v1", "materialized project pack required")
    for name, sha in manifest["files"].items():
        C.require(Path(name).name == name, "flat project pack input required")
        C.pin({"path": str(pack / name), "sha256": sha})
    mode = C.read_json(pack / "mode.json")
    policy = mode["model_policy"]
    C.require(policy["provider"] == "newapi" and policy["provider_model_id"] == "glm-5.3", "this provider adapter requires explicit newapi/glm-5.3; no fallback")
    root = a.output.absolute()
    C.require(not str(root).startswith("/mnt/"), "private Linux output required")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    bundle = root / "bundle"; bundle.mkdir(mode=0o700)
    for name in ("agent-roles.json", "team-binding.mjs"):
        shutil.copyfile(pack / name, bundle / name)
    fs_anchor = modules / "@deepseek-ai/dsh-fs-sandbox/lib/index.js"
    mode["managed_filesystem"].update(provider_module=str(PRESET / "exact-leaf-filesystem.mjs"), native_sdk_entry=str(fs_anchor))
    mode["managed_bridge"]["entrypoint"] = str(PRESET / "managed-bridge.mjs")
    mode["managed_model_transport"]["loader"] = str(PRESET / "model-transport.mjs")
    C.write_json(bundle / "mode.json", mode)
    source = PRESET / "native-ioctl-deny.c"
    compiler = Path("/usr/bin/gcc").resolve(strict=True)
    guard = root / "native-ioctl-deny"
    compiled = subprocess.run([str(compiler), "-std=c11", "-O2", "-static", "-Wall", "-Wextra", "-Werror",
        str(source), "-o", str(guard)], capture_output=True, timeout=30)
    (root / "guard-compile.stderr").write_bytes(compiled.stderr)
    C.require(compiled.returncode == 0, "native inherited ioctl guard compilation failed")
    guard.chmod(0o555)
    system_package = modules / f"@deepseek-ai/node-addon-system-{sys.platform}-{'x64' if os.uname().machine == 'x86_64' else 'arm64'}"
    launcher = root / "landlock-run"
    shutil.copyfile(system_package / "bin/landlock-run", launcher); launcher.chmod(0o555)
    probes = {}
    for name, program in (("landlock", launcher), ("ioctl", guard)):
        result = subprocess.run([str(program), "--probe"], capture_output=True, timeout=5)
        (root / (name + "-probe.stdout")).write_bytes(result.stdout)
        (root / (name + "-probe.stderr")).write_bytes(result.stderr)
        C.require(result.returncode == 0, "native confinement probe failed")
        probes[name] = {"exit_code": result.returncode, "stdout_sha256": __import__('hashlib').sha256(result.stdout).hexdigest()}
        if name == "landlock":
            C.require(result.stdout.strip() in (b"landlock: fully enforced", b"landlock: partially enforced (older ABI)"), "unknown native confinement verdict")
        else:
            value = json.loads(result.stdout)
            C.require(value.get("landlock_abi", 0) >= 3 and value.get("ioctl_after_errno") == 1
                and value.get("child_exec_ioctl_denied") is True, "inherited ioctl denial unproven")
    anchor = modules / "@deepseek-ai/dsh-sandbox-local/lib/index.js"
    sandbox = {"module_anchor": str(anchor), "module_anchor_sha256": C.digest(anchor),
        "launcher": str(launcher), "launcher_sha256": C.digest(launcher), "ioctl_guard": str(guard),
        "ioctl_guard_sha256": C.digest(guard), "probe_timeout_ms": 2000}
    selected = [{"id": "agent-default-model", "config": {"provider": "newapi", "model": "glm-5.3", "reasoningEffort": "max"}},
        {"id": "llm-pi-ai", "config": {"providers": {"newapi": {"api": "anthropic-messages",
            "apiKeyEnv": "FORGEFLOW_MODEL_RELAY_DUMMY", "baseURL": "http://forgeflow-model.invalid",
            "compat": {"forceAdaptiveThinking": True}, "models": [{"id": "glm-5.3", "name": "GLM-5.3 Max",
                "contextWindow": 1000000, "maxTokens": 131072, "input": ["text"],
                "reasoningEfforts": {"low": "low", "high": "high", "max": "max"}}]}}}}]
    C.write_json(root / "selected-model.json", selected)
    C.write_json(root / "credentials.json", {"version": 1, "refs": {"FORGEFLOW_MODEL_RELAY_DUMMY": "forgeflow-relay-no-provider-secret"}})
    patch = yaml.safe_load((pack / "cordis.patch.yml").read_text())
    patch += [{"id": "sandbox", "disabled": True}, {"insert": [{"id": "forgeflow-native-landlock",
        "name": str(PRESET / "managed-sandbox.mjs"), "config": sandbox}]},
        {"id": "fs-sandbox", "disabled": True}, {"insert": [{"id": "forgeflow-exact-leaf-filesystem",
            "name": str(PRESET / "exact-leaf-filesystem.mjs"), "config": {"module_anchor": str(fs_anchor),
                "module_anchor_sha256": C.digest(fs_anchor), "max_write_bytes": 16777216}}]}]
    C.write_json(root / "preset.json", patch)
    home = root / "doctor-home"; profile_home = home / "profiles/headless"
    profile_home.mkdir(mode=0o700, parents=True)
    C.write_json(home / "cordis.patch.yml", selected)
    shutil.copyfile(root / "credentials.json", home / ".credentials.yaml")
    C.write_json(profile_home / "package.json", {"name": "forgeflow-private-headless", "private": True,
        "dependencies": {}, "dsh": {"profile": {"bundles": ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-headless"]}}})
    C.write_json(profile_home / "cordis.patch.yml", [])
    (profile_home / "node_modules").symlink_to(modules, target_is_directory=True)
    bridge = [{"insert": [{"id": "forgeflow-managed-children", "name": str(PRESET / "managed-bridge.mjs"),
        "config": {"socket_path": "/tmp/forgeflow/controller.sock", "rpc_timeout_ms": 15000,
            "project_id": manifest["project_id"], "task_id": "doctor-only", "attempt_id": "doctor-only", "generation": 1}}]}]
    C.write_json(root / "doctor-bridge.json", bridge)
    command = [str(node), "--import", str(PRESET / "model-transport.mjs"), str(entry), "--profile", "headless",
        "--patch", str(root / "preset.json"), "--patch", str(root / "doctor-bridge.json"), "--dump-config"]
    process = subprocess.run(command, env={"PATH": "/usr/bin:/bin", "HOME": str(home), "DSH_HOME": str(home),
        "LANG": "C.UTF-8", "FORGEFLOW_MODEL_RELAY_DUMMY": "forgeflow-relay-no-provider-secret"},
        cwd=root, capture_output=True, timeout=60)
    (root / "composition.yaml").write_bytes(process.stdout)
    (root / "composition.stderr").write_bytes(process.stderr)
    C.require(process.returncode == 0 and process.stdout, "actual installed native dump-config failed; retained private diagnostics")
    C.require(all(s.encode() in process.stdout for s in ("forgeflow-managed-children", "forgeflow-native-landlock",
        "forgeflow-team-binding", "agent-team", "workflow-ptc", "forgeflow-exact-leaf-filesystem")), "actual native composition omitted required plugins")
    # The pi-ai closure is separately bound because the runtime validates its
    # transport parser and SDK dependencies. The complete CLI dependency closure
    # captures every installed package referenced by the selected runtime.
    sdk = N.installed_runtime_package_closure(modules / "@earendil-works/pi-ai")
    closure = N.installed_runtime_package_closure(package.parent)
    C.write_json(root / "sdk-closure.json", sdk)
    C.write_json(root / "runtime-closure.json", closure)
    pins = {path: row["sha256"] for path, row in closure["files"].items()}
    pins.update({path: row["sha256"] for path, row in sdk["files"].items()})
    for path in [node, source, compiler, guard, launcher, anchor, root / "selected-model.json", root / "credentials.json",
            root / "preset.json", root / "sdk-closure.json", root / "runtime-closure.json", root / "composition.yaml",
            *bundle.iterdir(), *PRESET.glob("*.mjs")]:
        pins[str(path.resolve())] = C.digest(path)
    doctor = {"schema_version": "forgeflow.managed-doctor.v1", "mode_id": mode["id"],
        "executor_profile_id": a.profile_id, "native_profile": "headless", "bridge_schema_version": "forgeflow.dsh-bridge.v2",
        "runtime_package": str(package), "runtime_version": runtime["version"], "exit_code": process.returncode,
        "composition_sha256": C.digest(root / "composition.yaml"), "artifact_sha256": pins.copy(), "command": command,
        "raw_composition_path": str(root / "composition.yaml"), "created_at": datetime.now(timezone.utc).isoformat(),
        "qualification": "NOT_RUN", "scope": "Actual installed npm runtime/configuration and confinement probes only; zero models/sessions",
        "sdk_runtime_closure": {k: sdk[k] for k in ("seed_package", "resolution", "package_count", "file_count", "total_bytes", "missing_optional_dependencies")}}
    doctor["sdk_runtime_closure"].update(manifest_path=str(root / "sdk-closure.json"), manifest_sha256=C.digest(root / "sdk-closure.json"))
    C.write_json(root / "doctor.json", doctor)
    pins[str(root / "doctor.json")] = C.digest(root / "doctor.json")
    profile = {"id": a.profile_id, "program": str(node), "prefix_args": [str(entry)], "home": str(home),
        "profile_name": "headless", "artifact_pins": [{"path": path, "sha256": sha} for path, sha in sorted(pins.items())],
        "resume_verified": False, "model_route_id": policy["route_id"], "gateway_coverage_verified": False}
    provider_policy = PRESET / "provider-policy.json"
    # Provider policy is explicit adapter data and included in the same pin set.
    profile["artifact_pins"].append({"path": str(provider_policy), "sha256": C.digest(provider_policy)})
    doctor["artifact_sha256"][str(provider_policy)] = C.digest(provider_policy)
    # Finalize the Doctor once, then replace its sole profile pin before export.
    (root / "doctor.json").unlink(); C.write_json(root / "doctor.json", doctor)
    for reference in profile["artifact_pins"]:
        if reference["path"] == str(root / "doctor.json"): reference["sha256"] = C.digest(root / "doctor.json")
    managed = {"mode_id": mode["id"], "mode_manifest": str(bundle / "mode.json"), "preset_patch": str(root / "preset.json"),
        "bridge_plugin": str(PRESET / "managed-bridge.mjs"), "selected_model_config": str(root / "selected-model.json"),
        "credentials": str(root / "credentials.json"), "doctor": str(root / "doctor.json"), "rpc_timeout_ms": 15000,
        "model_relay": {"schema_version": "forgeflow.model-uds.v1", "transport_loader": str(PRESET / "model-transport.mjs"),
            "sdk_origin": "http://forgeflow-model.invalid", "max_request_bytes": 8388608, "response_idle_timeout_ms": 300000,
            "provider_policy_id": "glm-5.3-max.v1", "provider_policy_path": str(provider_policy)}}
    C.write_json(root / "headless-profile.json", profile)
    C.write_json(root / "managed-config.json", managed)
    C.write_json(root / "executor-registration.json", {**profile, "kind": "DSH_MANAGED", "native_mode": managed})
    result = {"status": "PINNED_INSTALLED_NATIVE_CONFIGURATION", "runtime_version": runtime["version"],
        "project_id": manifest["project_id"], "profile_id": a.profile_id, "positions": manifest["positions"],
        "runtime_pins": len(profile["artifact_pins"]), "runtime_bytes": closure["total_bytes"], "probes": probes,
        "models_started": 0, "sessions_started": 0, "g20": "NOT_RUN", "runtime_business_qualification": "NOT_RUN"}
    C.write_json(root / "receipt.json", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project-pack", required=True, type=Path)
    p.add_argument("--node-modules", required=True, type=Path)
    p.add_argument("--node", type=Path, default=Path("/usr/bin/node"))
    p.add_argument("--profile-id", required=True)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    try:
        C.require(C.ID.fullmatch(a.profile_id), "valid profile ID required")
        print(json.dumps(freeze(a))); return 0
    except Exception as error:
        print(json.dumps({"status": "BLOCKED", "error_type": type(error).__name__,
            "reason": str(error) if isinstance(error, C.Blocked) else "Private original preparation diagnostics retained", "g20": "NOT_RUN"})); return 2


if __name__ == "__main__": sys.exit(main())
