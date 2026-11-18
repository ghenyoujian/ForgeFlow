#!/usr/bin/env bash
set -euo pipefail
source_root=$(cd "$(dirname "$0")/.." && pwd)
usage() {
  cat <<'EOF'
Usage: FORGEFLOW_INSTALL_ROOT=/fresh/version ops/install-local.sh \
         --checkpoint /path/to/receipt.json [--console-dist /path/to/dist]
         [--source-archive /path/to/source.tar.gz --source-archive-sha256 SHA]
         [--source-prefix ForgeFlow/control]
         [--legacy-archive /path/to/baseline.tar.gz --legacy-archive-sha256 SHA]
         [--design-plan /path/to/design.md --design-plan-sha256 SHA]
         [--evidence-index /path/to/index.json --evidence-index-sha256 SHA]
         [--evidence-root /path/to/source/root]
       FORGEFLOW_INSTALL_ROOT=/fresh/version ops/install-local.sh --package /path/to/package

Installs four pinned binaries, including forgeflow-sandbox-guard, and the built
console. It never runs Cargo/npm, starts a service, or overwrites an existing
directory. Build a checkpoint and console separately before installation.
EOF
}
checkpoint= package= console_dist="$source_root/console/dist"
delivery_args=()
while (($#)); do
  case "$1" in
    --checkpoint|--package|--console-dist)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      case "$1" in
        --checkpoint) checkpoint=$2 ;;
        --package) package=$2 ;;
        --console-dist) console_dist=$2 ;;
      esac
      shift 2 ;;
    --source-archive|--source-archive-sha256|--source-prefix|--legacy-archive|--legacy-archive-sha256|--design-plan|--design-plan-sha256|--evidence-index|--evidence-index-sha256|--evidence-root)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      delivery_args+=("$1" "$2")
      shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n "$checkpoint" && -z "$package" || -n "$package" && -z "$checkpoint" ]] || { usage >&2; exit 2; }
prefix=${FORGEFLOW_INSTALL_ROOT:?set explicit fresh FORGEFLOW_INSTALL_ROOT}
[[ "$prefix" = /* ]] || { echo 'Installation root must be absolute.' >&2; exit 2; }
[[ ! -e "$prefix" && ! -L "$prefix" ]] || { echo 'Installation directory exists; select a fresh version directory.' >&2; exit 1; }
if [[ -n "$checkpoint" ]]; then
  python3 "$source_root/ops/package-checkpoint.py" create \
    --receipt "$checkpoint" --console-dist "$console_dist" --output "$prefix" --source-root "$source_root" \
    "${delivery_args[@]}"
else
  [[ ${#delivery_args[@]} -eq 0 ]] || { echo 'Source/evidence options belong to checkpoint creation; the package already contains its pinned files.' >&2; exit 2; }
  python3 "$source_root/ops/package-checkpoint.py" install --package "$package" --prefix "$prefix"
fi
printf 'Installed pinned binaries/resources at %s; no services were started.\n' "$prefix"
