# CPU C++20 native business probe

`verification/native_build_probe.py` is a Root-reviewed executable verifier adapter,
not a model tool or a source of resource authority. It builds actual declared
candidate C++ translation units together with an independently published C++ probe,
executes a registered input case, and returns that program's actual JSON value and
exit status. It never emits a business PASS, substitutes a filesystem assertion,
grants a build permit or certifies an SDK/GPU/Windows capability.

## Fixed process recipe

The existing `forgeflow.splatforge-card-recipe.v1` process case executes the exact
approved Python interpreter with this argument list and no extra arguments:

```text
-I -B <absolute pinned runner> --spec <absolute frozen role-spec.json> --case <registered case name>
```

The interpreter, runner, role specification, independent probe, toolchain manifest
and every compiler/SDK file named by that manifest must be approved immutable
verification inputs. All belong in `VerificationPlan.bound_inputs`; declarations
alone do not establish their actual availability. The publication policy may allow
this exact typed runner without allowing arbitrary processes, Python scripts,
shells, compiler flags, or subprocess/FFI imports in generated unittest suites.

The existing process case's `stdin_utf8` becomes the actual native program's stdin.
The native program is invoked as `<compiled-probe> --case <name>`. Its stdout must
be exactly one JSON object or array with unique keys and finite numbers. The
adapter emits canonical JSON for comparison by the existing process verifier with
`case.expected.stdout_json`. Native exit codes such as `0` or `2` remain actual
exit codes and must match the recipe's independent expected value. Exit `125` is
reserved for adapter/capability failure and cannot be an accepted expected result.
No error result includes successful business credit. Program stderr and compiler
diagnostics remain raw command evidence. Exit zero by itself is insufficient.

## Exact role specification

```json
{
  "schema_version": "forgeflow.native-build-probe.v1",
  "capability": "cpu-cxx20",
  "card_id": "<unchanged original card>",
  "source_card_sha256": "<unchanged canonical source-card SHA256>",
  "toolchain": {"path": "<absolute approved manifest>", "sha256": "<actual SHA256>"},
  "source_files": [
    {"path": "core/example.cpp", "kind": "translation_unit"},
    {"path": "core/example.hpp", "kind": "header"}
  ],
  "include_directories": ["."],
  "probe": {"path": "<absolute frozen independent probe.cpp>", "sha256": "<actual SHA256>"},
  "cases": [{"name": "valid_input", "timeout_seconds": 10}, {"name": "invalid_input", "timeout_seconds": 10}],
  "limits": {
    "compile_timeout_seconds": 120,
    "max_output_bytes": 1048576,
    "max_source_bytes": 16777216,
    "max_build_bytes": 268435456
  }
}
```

`validate_spec(value)` and `validate_toolchain(value)` are pure structural validators
for trusted publication code; they do not read files or assert environment readiness.
The former requires 1–256 unique product source files, up to 32 explicit include
directories, and 1–64 unique cases. Header-only production contracts are supported:
the independent probe must include those actual headers, and compiler dependency
records must demonstrate that every declared source/header participated. Empty
translation units and author tests are not substitutes for production code.
Cases use names matching `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`. Case runtime is bounded
at 120 seconds; total toolchain discovery/compilation/linking is bounded at 300
seconds per invocation. Source, output and build limits cannot exceed 16 MiB,
1 MiB and 512 MiB respectively. Include paths and source paths cannot escape their
canonical relative territory; source paths cannot contain whitespace.

The publisher must additionally prove that source files are within the original
card's exact admitted read/write scope, that actual native production outputs are
included, and that every original positive/negative/fault assertion maps to
specific independently reviewed cases. The three role probes/specifications must
retain independent authorship and distinct bytes. Generated role specs may refer
to an authorized source-relative probe while under review. Before validation the
publisher resolves that path in a copy; on publication it freezes the probe,
rewrites only the approved probe pin, and freezes the derived role spec. Preserve
both the original reviewed spec SHA and the final derived spec SHA in publication
provenance. Never overwrite the reviewed source file to conceal this translation.

A process case's outer timeout must cover the specified compile timeout plus case
runtime and startup overhead; the role timeout must cover all its registered
cases. Existing recipe limits still apply. The Core's independently admitted
build-capable resource profile and actual reservation must authorize compilation;
the runner neither acquires nor fabricates `build_permit`. The caller supplies the
actual read-only candidate root through `SPLATFORGE_SOURCE_ROOT`, matching cwd, and
a separate admitted scratch directory through `SPLATFORGE_VERIFIER_SCRATCH`.
Standalone runs have no acceptance authority.

## Actual toolchain manifest

```json
{
  "schema_version": "forgeflow.native-cxx-toolchain.v1",
  "capability": "cpu-cxx20",
  "platform": {"os": "linux", "machine": "x86_64"},
  "compiler": {"path": "<canonical real GCC C++ executable>", "sha256": "<actual SHA256>"},
  "files": [{"path": "<canonical compiler/backend/linker/SDK file>", "sha256": "<actual SHA256>"}]
}
```

`files` must include the compiler itself and the complete approved runtime/SDK
closure required by the chosen card. Runtime checks hash all listed files and
match the actual Linux architecture. The adapter resolves GCC's real `cc1plus`,
assembler, `collect2`, linker and fixed normal Linux link inputs through bounded
read-only compiler queries; unlisted components prevent execution. Every actual
dynamic runtime library reported by the approved `ldd` inspector must also belong
to the pinned closure, for both toolchain executables and the linked probe.
Every actual
header recorded by GCC `-MD` must be either an explicitly copied product/probe
source or a pinned SDK file. A missing dependency is `TOOLCHAIN_INCOMPLETE`, not a
successful or skipped business case. A compiler hash does not certify arbitrary
SDKs; adding headers/libraries requires a new approved actual manifest.

The command construction is fixed: GCC `-std=c++20 -O0 -g0`, bounded diagnostics,
dependency recording, approved relative include directories, individual `-c`
compilations, then one link. No generated flag list, environment override, shell
fragment or arbitrary executable is accepted. The sanitized environment excludes
`CPATH`, compiler wrappers, `LD_PRELOAD` and user toolchain configuration.

Each invocation copies only its declared native sources into a private temporary
source view. It compiles only these translation units and the independent probe,
uses file-backed bounded logs, applies an output file-size limit, checks aggregate
scratch growth, and terminates owned process groups on timeout/failure. The outer
Core cgroup remains authoritative for the complete descendant lifecycle. Temporary
sources, objects, logs and executable are removed on normal success or failure;
original command stdout/stderr remain in the supervising verifier's evidence.
Source/probe/toolchain hashes are checked after execution. There is no persistent
mutable compiler cache in this initial adapter and no workspace-wide build.

This first profile supports CPU C++20 on actual Linux only. Qt-specific SDK/runtime,
GPU device access, CUDA/HLSL compilation and Windows execution need separately
reviewed real environment profiles and admission. They must remain explicitly
blocked until available. A local positive/negative runner check demonstrates only
the adapter; one original card's actual DSH author/review/integration receipts are
still required before claiming any of the 2,884 original cards complete.
