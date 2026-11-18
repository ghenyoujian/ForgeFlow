from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "ops" / "ecp"))
import normalized_policy as policy
import source_snapshot


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def fixture():
    head = "a" * 40
    projection = {
        "version": "forgeflow.ecp-directory-projection.v1", "mode_availability": "UNAVAILABLE",
        "exclusion_policy_sha256": policy.canonical_sha256(list(source_snapshot.V3_EXCLUDES)),
        "directories": [{"path": ".", "kind": "directory", "mode": None, "origin": "source_root"},
                        {"path": "assets", "kind": "directory", "mode": None, "origin": "git_ancestor"}],
        "excluded_directory_boundaries": [{"path": ".git", "kind": "directory", "excluded_by": ".git/"}],
    }
    manifest = {
        "schema_version": "forgeflow.ecp-source-manifest.v3", "source_root": "/fixture/source", "head": head,
        "worktree_state": "CLEAN", "exclude_patterns": list(source_snapshot.V3_EXCLUDES),
        "untracked_scan_mode": "bounded", "untracked_scan_roots": list(source_snapshot.EXPAND_UNTRACKED_PREFIXES),
        "tracked_changes": [], "untracked_business_files": [], "excluded_generated_files": [],
        "patch_sha256": hashlib.sha256(b"").hexdigest(), "manifest_sha256": "",
        "created_at": "2026-11-16T00:00:00Z", "release_qualifiable": False,
        "inventory_complete": True, "inventory_error": None, "index_visibility_exceptions": [],
        "directory_projection": projection, "projection_sha256": policy.canonical_sha256(projection),
    }
    rehash_manifest(manifest)
    entries = []
    for path, mode, data in (("assets/run", "100755", b"run\n"), ("assets/text", "100644", b"text\n")):
        entries.append({"path": path, "kind": "file", "git_mode": mode, "git_oid": blob(data),
                        "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    target = b"assets/text"
    entries.append({"path": "latest", "kind": "symlink", "git_mode": "120000", "git_oid": blob(target),
                    "size": len(target), "sha256": hashlib.sha256(target).hexdigest(), "target": target.decode()})
    supplement = {
        "schema_version": policy.SUPPLEMENT_SCHEMA, "source_manifest_sha256": manifest["manifest_sha256"],
        "source_head": head, "source_mode_claim": "UNKNOWN",
        "directories": [{"path": x["path"], "origin": x["origin"]} for x in projection["directories"]],
        "entries": entries, "qualification": "NOT_RUN", "product_gate_effect": "NONE",
    }
    attrs = {"access_acl": "ABSENT", "default_acl": "ABSENT", "xattrs": "NONE", "hardlinks": "REJECT",
             "symlinks": "INTERNAL_PROJECTION_ONLY", "umask": "0077"}
    limits = {"max_entries": 100, "max_file_bytes": 4096, "max_total_bytes": 8192, "max_depth": 16}
    rules = {"directory_modes": {".": "0700", "assets": "0750"},
             "file_modes": {"assets/run": "0750", "assets/text": "0640"},
             "uid": 1000, "gid": 1000, "attributes": attrs, "limits": limits}
    return manifest, supplement, rules


def rehash_manifest(manifest):
    manifest["projection_sha256"] = policy.canonical_sha256(manifest["directory_projection"])
    core = {k: v for k, v in manifest.items() if k not in ("manifest_sha256", "created_at", "release_qualifiable")}
    manifest["manifest_sha256"] = policy.canonical_sha256(core)


def update_target(item, target):
    raw = target.encode("utf-8")
    item.update(target=target, size=len(raw), sha256=hashlib.sha256(raw).hexdigest(), git_oid=blob(raw))


def symlink(path, target):
    item = {"path": path, "kind": "symlink", "git_mode": "120000"}
    update_target(item, target)
    return item


class NormalizationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.supplement, self.rules = fixture()

    def create(self):
        return policy.build_policy(self.manifest, self.supplement, **self.rules)

    def test_legacy_exclusion_policy_is_not_accepted_as_current_v3(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['exclude_patterns'] = list(source_snapshot.DEFAULT_EXCLUDES)
        manifest['directory_projection']['exclusion_policy_sha256'] = policy.canonical_sha256(
            list(source_snapshot.DEFAULT_EXCLUDES))
        rehash_manifest(manifest)
        supplement = copy.deepcopy(self.supplement)
        supplement['source_manifest_sha256'] = manifest['manifest_sha256']
        with self.assertRaisesRegex(policy.InvalidPolicy, 'source inventory policy mismatch'):
            policy.validate_source_supplement(manifest, supplement)

    def test_previous_v3_policy_and_mixed_digests_are_rejected(self):
        old = [x for x in source_snapshot.DEFAULT_EXCLUDES
               if x not in ('*.log', '*.png', '*.tar.gz', '*.pyc')]
        old_sha = policy.canonical_sha256(old)
        self.assertEqual(old_sha, 'f925995e05314920638da71b4ef93aeb2f88f88c656190efb190cd7917f636bd')
        self.assertEqual(policy.canonical_sha256(list(source_snapshot.V3_EXCLUDES)),
                         '693a01c306939936dea248c348d1ed09f44cfc230b27b7a6faeab85fb3926787')
        for patterns, digest in ((old, old_sha), (old, policy.canonical_sha256(list(source_snapshot.V3_EXCLUDES))),
                                 (list(source_snapshot.V3_EXCLUDES), old_sha)):
            with self.subTest(patterns=patterns, digest=digest):
                manifest = copy.deepcopy(self.manifest)
                manifest['exclude_patterns'] = patterns
                manifest['directory_projection']['exclusion_policy_sha256'] = digest
                rehash_manifest(manifest)
                supplement = copy.deepcopy(self.supplement)
                supplement['source_manifest_sha256'] = manifest['manifest_sha256']
                with self.assertRaises(policy.InvalidPolicy):
                    policy.validate_source_supplement(manifest, supplement)

    def test_boundary_names_as_regular_files_and_link_targets_are_valid(self):
        for name in ('evidence', 'target', 'node_modules'):
            with self.subTest(name=name):
                supplement = copy.deepcopy(self.supplement)
                data = ('business:' + name).encode()
                supplement['entries'].extend((
                    {'path': name, 'kind': 'file', 'git_mode': '100644', 'git_oid': blob(data),
                     'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()},
                    symlink('alias', name)))
                supplement['entries'].sort(key=lambda row: row['path'].encode('utf-8'))
                policy.validate_source_supplement(self.manifest, supplement)

    def test_boundary_named_symlink_is_rejected(self):
        for name in ('evidence', 'target', 'node_modules'):
            with self.subTest(name=name):
                supplement = copy.deepcopy(self.supplement)
                supplement['entries'].append(symlink(name, 'assets/text'))
                supplement['entries'].sort(key=lambda row: row['path'].encode('utf-8'))
                with self.assertRaisesRegex(policy.InvalidPolicy, 'excluded source file'):
                    policy.validate_source_supplement(self.manifest, supplement)

    def test_policy_symlink_limit_counts_outer_link(self):
        for internal, usable in ((39, True), (40, False)):
            with self.subTest(internal_links=internal):
                supplement = copy.deepcopy(self.supplement)
                for i in range(internal):
                    target = f'link-{i+1:02d}' if i+1 < internal else 'text'
                    supplement['entries'].append(symlink(f'assets/link-{i:02d}', target))
                supplement['entries'].append(symlink('assets/outer', 'link-00'))
                supplement['entries'].sort(key=lambda row: row['path'].encode('utf-8'))
                if usable:
                    policy.validate_source_supplement(self.manifest, supplement)
                else:
                    with self.assertRaisesRegex(policy.InvalidPolicy, 'symlink cycle or too many links'):
                        policy.validate_source_supplement(self.manifest, supplement)

    def test_explicit_policy_is_deterministic_and_unqualified(self):
        value = self.create()
        self.assertEqual(value, self.create())
        self.assertEqual(value["source_mode_claim"], "UNKNOWN")
        self.assertEqual((value["authority"], value["status"], value["qualification"], value["product_gate_effect"]),
                         ("UNVERIFIED", "DRAFT", "NOT_RUN", "NONE"))
        self.assertIsNone(next(x for x in value["entries"] if x["kind"] == "symlink")["mode"])
        pin = policy.canonical_sha256(value)
        policy.validate_policy(value, self.manifest, self.supplement, pin)
        self.assertEqual(policy.parse_unique_json(policy.canonical_bytes(value)), value)

    def test_external_digest_and_source_bindings_are_mandatory(self):
        value = self.create()
        pin = policy.canonical_sha256(value)
        self.assertRaises(policy.InvalidPolicy, policy.validate_policy, value, self.manifest, self.supplement, "0" * 64)
        changed = copy.deepcopy(value); changed["owner"]["uid"] = 1001
        self.assertRaises(policy.InvalidPolicy, policy.validate_policy, changed, self.manifest, self.supplement, pin)
        changed_s = copy.deepcopy(self.supplement); changed_s["entries"][0]["sha256"] = "0" * 64
        self.assertRaises(policy.InvalidPolicy, policy.validate_policy, value, self.manifest, changed_s, pin)
        changed_m = copy.deepcopy(self.manifest); changed_m["head"] = "b" * 40
        self.assertRaises(policy.InvalidPolicy, policy.validate_policy, value, changed_m, self.supplement, pin)

    def test_null_git_object_ids_cannot_be_asserted(self):
        source = copy.deepcopy(self.supplement)
        source["entries"][0]["git_oid"] = "0" * 40
        self.assertRaises(policy.InvalidPolicy, policy.validate_source_supplement, self.manifest, source)
        manifest = copy.deepcopy(self.manifest)
        manifest["head"] = "0" * 40
        rehash_manifest(manifest)
        source = copy.deepcopy(self.supplement)
        source["source_head"] = manifest["head"]
        source["source_manifest_sha256"] = manifest["manifest_sha256"]
        self.assertRaises(policy.InvalidPolicy, policy.validate_source_supplement, manifest, source)

    def test_raw_parser_rejects_duplicates_floats_and_oversized_integers(self):
        for raw in (b'{"uid":1,"uid":2}', b'{"value":1.0}', b'{"value":NaN}',
                    b'{"value":-1}', b'{"value":123456789012345678901}', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(policy.InvalidPolicy):
                policy.parse_unique_json(raw)
        with self.assertRaises(policy.InvalidPolicy):
            policy.canonical_bytes({"bad": "\ud800"})

    def test_no_implicit_or_extra_mode_rules(self):
        for key, path in (("directory_modes", "assets"), ("file_modes", "assets/run")):
            with self.subTest(key=key):
                rules = copy.deepcopy(self.rules); rules[key].pop(path)
                self.assertRaises(policy.InvalidPolicy, policy.build_policy, self.manifest, self.supplement, **rules)
        rules = copy.deepcopy(self.rules); rules["file_modes"]["unexpected"] = "0640"
        self.assertRaises(policy.InvalidPolicy, policy.build_policy, self.manifest, self.supplement, **rules)

    def test_modes_preserve_git_executable_class_and_reject_special_bits(self):
        for path, value in (("assets/run", "0641"), ("assets/run", "4755"), ("assets/text", "0750"),
                            ("assets/text", "640"), ("assets/text", 0o640)):
            with self.subTest(path=path, value=value):
                rules = copy.deepcopy(self.rules); rules["file_modes"][path] = value
                self.assertRaises(policy.InvalidPolicy, policy.build_policy, self.manifest, self.supplement, **rules)

    def test_unsupported_attributes_identity_and_budgets_rejected(self):
        for key, value in (("uid", True), ("gid", -1), ("uid", 2**32 - 1)):
            with self.subTest(key=key, value=value):
                rules = copy.deepcopy(self.rules); rules[key] = value
                self.assertRaises(policy.InvalidPolicy, policy.build_policy, self.manifest, self.supplement, **rules)
        for key, value in (("access_acl", "UNOBSERVED"), ("default_acl", "ALLOW"), ("hardlinks", "ALLOW"),
                           ("xattrs", "UNKNOWN"), ("symlinks", "UNSAFE"), ("umask", "0000")):
            with self.subTest(attribute=key):
                rules = copy.deepcopy(self.rules); rules["attributes"][key] = value
                self.assertRaises(policy.InvalidPolicy, policy.build_policy, self.manifest, self.supplement, **rules)
        for key, value in (("max_entries", 0), ("max_entries", True), ("max_file_bytes", 1),
                           ("max_total_bytes", 1), ("max_depth", 1), ("max_depth", 129)):
            with self.subTest(limit=key, value=value):
                rules = copy.deepcopy(self.rules); rules["limits"][key] = value
                self.assertRaises(policy.InvalidPolicy, policy.build_policy, self.manifest, self.supplement, **rules)

    def test_total_path_and_symlink_work_is_bounded(self):
        with patch.object(policy, "MAX_PATH_OPERATIONS", 2):
            with self.assertRaisesRegex(policy.InvalidPolicy, "total source path depth"):
                policy.validate_source_supplement(self.manifest, self.supplement)
        with patch.object(policy, "MAX_PATH_OPERATIONS", 1):
            with self.assertRaisesRegex(policy.InvalidPolicy, "total symlink resolution"):
                policy._verify_links({".", "assets"}, self.supplement["entries"])

    def test_manifest_projection_cannot_invent_source_modes(self):
        for change in ("verified", "synthetic_mode", "modified_digest"):
            with self.subTest(change=change):
                manifest = copy.deepcopy(self.manifest); supplement = copy.deepcopy(self.supplement)
                if change == "verified": manifest["directory_projection"]["mode_availability"] = "VERIFIED"
                elif change == "synthetic_mode": manifest["directory_projection"]["directories"][0]["mode"] = "0755"
                else: manifest["projection_sha256"] = "0" * 64
                if change != "modified_digest": rehash_manifest(manifest)
                supplement["source_manifest_sha256"] = manifest["manifest_sha256"]
                self.assertRaises(policy.InvalidPolicy, policy.validate_source_supplement, manifest, supplement)

    def test_path_sets_are_canonical_unique_and_complete(self):
        variants = []
        wrong_dir = copy.deepcopy(self.supplement); wrong_dir["directories"][1]["origin"] = "excluded_container"; variants.append(wrong_dir)
        duplicate = copy.deepcopy(self.supplement); duplicate["entries"].append(copy.deepcopy(duplicate["entries"][-1])); variants.append(duplicate)
        reorder = copy.deepcopy(self.supplement); reorder["entries"].reverse(); variants.append(reorder)
        missing_parent = copy.deepcopy(self.supplement); missing_parent["entries"][0]["path"] = "absent/run"; variants.append(missing_parent)
        traversal = copy.deepcopy(self.supplement); traversal["entries"][0]["path"] = "../escape"; variants.append(traversal)
        for index, value in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(policy.InvalidPolicy):
                policy.validate_source_supplement(self.manifest, value)

    def test_git_ancestor_directory_must_have_an_included_entry(self):
        value = copy.deepcopy(self.supplement)
        item = copy.deepcopy(value["entries"][0]); item["path"] = "run"
        value["entries"] = [item]
        with self.assertRaisesRegex(policy.InvalidPolicy, "directory origin"):
            policy.validate_source_supplement(self.manifest, value)

    def test_symlink_escape_cycle_and_content_forgery_are_rejected(self):
        for target in ("/absolute", "../escape", "latest", "missing", "assets/../../escape", "target\\bad"):
            with self.subTest(target=target):
                value = copy.deepcopy(self.supplement); update_target(value["entries"][-1], target)
                self.assertRaises(policy.InvalidPolicy, policy.validate_source_supplement, self.manifest, value)
        value = copy.deepcopy(self.supplement); value["entries"][-1]["sha256"] = "0" * 64
        self.assertRaises(policy.InvalidPolicy, policy.validate_source_supplement, self.manifest, value)

    def test_directory_symlink_graph_rejects_recursive_walks(self):
        for links in ((symlink("loop", "."),),
                      (symlink("A", "B"), symlink("B", "A")),
                      (symlink("assets/back", ".."),)):
            with self.subTest(links=links):
                source = copy.deepcopy(self.supplement)
                source["entries"].extend(links)
                source["entries"].sort(key=lambda x: x["path"].encode("utf-8"))
                self.assertRaises(policy.InvalidPolicy, policy.validate_source_supplement, self.manifest, source)
        source = copy.deepcopy(self.supplement)
        source["entries"].append(symlink("alias", "assets"))
        source["entries"].sort(key=lambda x: x["path"].encode("utf-8"))
        policy.validate_source_supplement(self.manifest, source)

    def test_cross_directory_alias_cycle_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["directory_projection"]["directories"].append(
            {"path": "other", "kind": "directory", "mode": None, "origin": "git_ancestor"})
        rehash_manifest(manifest)
        source = copy.deepcopy(self.supplement)
        source["source_manifest_sha256"] = manifest["manifest_sha256"]
        source["directories"].append({"path": "other", "origin": "git_ancestor"})
        source["entries"].extend((symlink("assets/to_other", "../other"),
                                  symlink("other/to_assets", "../assets")))
        source["entries"].sort(key=lambda x: x["path"].encode("utf-8"))
        with self.assertRaisesRegex(policy.InvalidPolicy, "graph contains a cycle"):
            policy.validate_source_supplement(manifest, source)

    def test_policy_cannot_claim_qualification_or_add_fields(self):
        for key, value in (("authority", "VERIFIED"), ("status", "PASS"), ("qualification", "PASS"),
                           ("product_gate_effect", "GRANTED"), ("unexpected", True)):
            with self.subTest(key=key):
                p = self.create(); p[key] = value
                self.assertRaises(policy.InvalidPolicy, policy.validate_policy, p, self.manifest,
                                  self.supplement, policy.canonical_sha256(p))


if __name__ == "__main__":
    unittest.main()
