#!/usr/bin/env bash
# Verify OSV-backed correlation fixtures with OSV-Scanner.
#
# Requirements:
#   - Bash 4+
#   - jq
#   - osv-scanner 2.x (tested with 2.6.0)
#   - Network access to OSV.dev, unless a local vulnerability database is used
#
# Usage:
#   etc/test-data/correlation/verify-osv.sh
#   OSV_SCANNER_OFFLINE=1 etc/test-data/correlation/verify-osv.sh
#
# This is an optional fixture sanity check, not the correlation test oracle.
# For each artifact-level expectation in expected.json, an `affected` ID must
# be reported by OSV-Scanner; `none`, `fixed`, and `not_affected` IDs must not
# be reported. The Rust tests use the pinned advisory files in this directory.
# OSV-Scanner uses its own vulnerability database and may therefore report newer
# findings. Direct component expectations, CPE/checksum cases, and non-OSV
# advisories are intentionally left to the Rust correlation tests.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CASES_DIR="$SCRIPT_DIR/cases"
OSV_SCANNER_BIN=${OSV_SCANNER_BIN:-osv-scanner}

command -v "$OSV_SCANNER_BIN" >/dev/null 2>&1 || {
    printf 'error: osv-scanner is required (set OSV_SCANNER_BIN to its path)\n' >&2
    exit 1
}
command -v jq >/dev/null 2>&1 || {
    printf 'error: jq is required\n' >&2
    exit 1
}

printf 'Using: '
"$OSV_SCANNER_BIN" --version | tr '\n' ' '
printf '\n'

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

scanner_args=(scan source --format json --verbosity error)
if [[ "${OSV_SCANNER_OFFLINE:-0}" == "1" ]]; then
    scanner_args+=(--offline --offline-vulnerabilities)
fi

verified=0

while IFS=$'\t' read -r case_id case_dir artifact expected; do
    [[ -n "$case_id" ]] || continue
    artifact_path="$case_dir/$artifact"
    [[ -f "$artifact_path" ]] || {
        printf 'error: missing SBOM: %s\n' "$artifact_path" >&2
        exit 1
    }

    result="$tmp_dir/result.json"
    stderr_file="$tmp_dir/stderr.log"
    set +e
    "$OSV_SCANNER_BIN" "${scanner_args[@]}" -L "$artifact_path" \
        >"$result" 2>"$stderr_file"
    scanner_status=$?
    set -e

    [[ -s "$result" ]] || {
        printf 'error: OSV-Scanner produced no JSON for %s\n' "$artifact_path" >&2
        cat "$stderr_file" >&2
        exit 1
    }
    jq empty "$result" >/dev/null || {
        printf 'error: invalid OSV-Scanner JSON for %s\n' "$artifact_path" >&2
        cat "$stderr_file" >&2
        exit 1
    }
    if ((scanner_status > 1)); then
        printf 'error: OSV-Scanner failed for %s\n' "$artifact_path" >&2
        cat "$stderr_file" >&2
        exit 1
    fi

    IFS=',' read -r -a assertions <<< "$expected"
    for assertion in "${assertions[@]}"; do
        [[ -n "$assertion" ]] || continue
        vulnerability=${assertion%%=*}
        expected_status=${assertion#*=}
        found=$(jq -r --arg id "$vulnerability" '
            [
                .results[]?.packages[]?.groups[]?.ids[]?,
                .results[]?.packages[]?.groups[]?.aliases[]?
            ] | unique | index($id) != null
        ' "$result")

        case "$expected_status" in
            affected)
                expected_found=true
                ;;
            *)
                expected_found=false
                ;;
        esac

        if [[ "$found" != "$expected_found" ]]; then
            printf 'mismatch: %s %s expected=%s scanner_found=%s\n' \
                "$case_id" "$artifact" "$vulnerability" "$found" >&2
            exit 1
        fi
    done

    printf 'verified %s: %s\n' "$case_id" "$artifact"
    verified=$((verified + 1))
done < <(
    for manifest in "$CASES_DIR"/*/expected.json; do
        manifest_dir=$(dirname "$manifest")
        jq -r --arg dir "$manifest_dir" '
            select(.ignored != true)
            | select(any([.advisories[]?.path][]; contains("/advisories/osv/")))
            | .id as $case_id
            | .sboms[]
            | .artifacts[] as $artifact
            | [$case_id, $dir, $artifact,
               (.expected | to_entries | map([.key, .value] | join("=")) | join(","))]
            | @tsv
        ' "$manifest"
    done
)

printf 'Verified %d SBOM artifacts.\n' "$verified"
