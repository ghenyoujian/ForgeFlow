#!/usr/bin/env python3
"""Create a project-sized native composition. Files only; no database/model/session writes."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
PRESETS = ROOT / "crates/executors/presets/forgeflow"
if not PRESETS.is_dir(): PRESETS = ROOT / "executors/presets/forgeflow"
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError("invalid project, role, owner, team or preset identity")
    return value


def validate_roster(catalog):
    identifier(catalog["project_id"])
    rows = catalog["roster"]
    if (catalog.get("schema_version") != "forgeflow.agent-roles.v1"
            or not isinstance(rows, list) or not 1 <= len(rows) <= 10000
            or type(catalog.get("positions")) is not int or catalog["positions"] != len(rows)):
        raise ValueError("project role count differs from the nonempty roster")
    for field in ("position_id", "preset_id", "teammate_name"):
        values = [identifier(row[field]) for row in rows]
        if len(set(values)) != len(values):
            raise ValueError("duplicate project role identity: " + field)
    for row in rows:
        identifier(row["owner_id"]); identifier(row["owner_team_id"])
        if row["role"] not in ("lead", "owner", "implementer", "verifier"):
            raise ValueError("unsupported role")
    return catalog


def composition(project, positions, provider, model, route, roster=None, active_limit=32):
    identifier(project)
    if type(positions) is not int or not 1 <= positions <= 10000:
        raise ValueError("positions must be 1..10000")
    if not all(isinstance(v, str) and v.strip() and len(v) <= 256 for v in (provider, model, route)):
        raise ValueError("an explicit provider, model and route are required")
    if type(active_limit) is not int or active_limit not in (1, 4, 10, 32, 64):
        raise ValueError("active limit must be one of1/4/10/32/64")
    active_limit = min(active_limit, positions)
    generic = {r: f"forgeflow-{r}-v1" for r in ("lead", "owner", "implementer", "verifier")}
    rows = []
    for i in range(positions):
        role = "lead" if i == 0 else "verifier" if i == positions - 1 else "implementer"
        rows.append({"position_id": f"agent-{i + 1:04d}", "teammate_name": f"agent-{i + 1:04d}",
            "preset_id": f"{project[:100]}-agent-{i + 1:04d}", "generic_preset_id": generic[role], "model_route": route,
            "owner_id": "owner", "owner_team_id": "project-team", "role": role,
            "specialty": "Project-approved finite delivery", "organizational_parent_position_id": None if i == 0 else "agent-0001"})
    catalog = validate_roster(roster or {"schema_version": "forgeflow.agent-roles.v1", "project_id": project,
        "positions": positions, "roster": rows, "teams": [{"owner_id": "owner", "team_id": "project-team", "planned_agents": positions}],
        "generic_presets": generic, "qualification": "NOT_RUN"})
    if catalog["project_id"] != project or catalog["positions"] != positions:
        raise ValueError("explicit roster belongs to another project or role count")
    mode = json.loads((PRESETS / "mode.json").read_text())
    mode.update(id=f"{project}-collaboration", project_id=project, name=f"ForgeFlow · {project}",
        native_root_binding_policy="IMPORTED_PLANNING_ROLE_V1")
    mode["role_catalog"].update(specialized_presets=positions, planned_positions=positions)
    mode["configured_limits"].update(team_members=positions, workflow_concurrent_agents=active_limit)
    mode["runtime_capacity_policy"].update(workflow_concurrent_agents=active_limit, team_member_names_per_native_team=positions)
    mode["model_policy"] = {"provider": provider, "provider_model_id": model, "route_id": route, "other_models_allowed": False}
    patch = yaml.safe_load((PRESETS / "cordis.patch.yml").read_text())
    templates = {}
    for row in patch:
        if row.get("id") == "workflow-ptc": row["config"]["maxConcurrentAgents"] = active_limit
        for entry in row.get("insert", []):
            if entry.get("id") == "agent-team": entry["config"]["maxMembers"] = positions
            if entry.get("name") == "@deepseek-ai/dsh-agent-preset": templates[entry["config"]["id"]] = entry
            if str(entry.get("name", "")).startswith("./"):
                entry["name"] = str((PRESETS / entry["name"]).resolve(strict=True))
            if entry.get("id") == "forgeflow-team-binding":
                entry["config"].update(bindings=catalog["roster"], default_root_position_id=catalog["roster"][0]["position_id"])
    specialized = []
    for role in catalog["roster"]:
        entry = copy.deepcopy(templates[role.get("generic_preset_id", generic[role["role"]])])
        entry["id"] = "preset-" + role["preset_id"]
        entry["config"].update(id=role["preset_id"], name=role["position_id"])
        specialized.append(entry)
    patch.insert(0, {"id": "agent-default-model", "config": {"provider": provider, "model": model}})
    patch.append({"insert": specialized})
    return mode, catalog, patch


def materialize(output, project, positions, provider, model, route, roster=None, active_limit=32):
    mode, catalog, patch = composition(project, positions, provider, model, route, roster, active_limit)
    output = Path(output).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / "team-binding.mjs").write_bytes((PRESETS / "team-binding.mjs").read_bytes())
    values = {"mode.json": mode, "agent-roles.json": catalog,
        "delivery-settings.json": {"planning_catalog_id": "project-plan", "expected_positions": positions,
            "expected_card_count": None, "model_display": model, "source_refs": {}, "native_panel_enabled": False}}
    for name, value in values.items():
        (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    (output / "cordis.patch.yml").write_text(yaml.safe_dump(patch, sort_keys=False, allow_unicode=True))
    # Project packs reference shared modules. The profile freezer must pin their
    # actual bytes, along with the runtime closure, before registration/admission.
    modules = {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in PRESETS.glob("*.mjs")}
    manifest = {"schema_version": "forgeflow.project-pack.v1", "project_id": project,
        "positions": positions, "active_limit": mode["configured_limits"]["workflow_concurrent_agents"], "qualification": "NOT_RUN", "runtime_started": False,
        "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.is_file()},
        "shared_module_pins": modules, "model_policy": mode["model_policy"]}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project-id", required=True)
    p.add_argument("--positions", type=int, required=True)
    p.add_argument("--provider", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--model-route", required=True)
    p.add_argument("--active-limit", type=int, choices=(1,4,10,32,64), default=32)
    p.add_argument("--roster", type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    try:
        result = materialize(a.output, a.project_id, a.positions, a.provider, a.model, a.model_route,
            json.loads(a.roster.read_text()) if a.roster else None, a.active_limit)
        print(json.dumps({"project_id": result["project_id"], "positions": result["positions"],
            "output": str(a.output), "qualification": result["qualification"], "runtime_started": False}))
    except (ValueError, KeyError, OSError) as error:
        print(json.dumps({"status": "BLOCKED", "error_type": type(error).__name__, "message": str(error)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
