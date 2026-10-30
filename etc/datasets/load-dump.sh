#!/usr/bin/env bash
#
# Download a Trustify dump and set it up for a locally running (cargo) backend.
#
# Usage: load-dump.sh [-f|--force] <dump-id>
#
#   <dump-id>     The dump's ID, e.g. 20261030T081751Z
#   -f, --force   Drop the database and delete the storage directory if they already contain data
#
# Expects the compose environment (etc/deploy/compose/compose.yaml) to be up already.
#
# Environment:
#   TRUSTIFY_DUMP_DIR      Download location, a sub-dir with the dump ID is created (default: $TMPDIR or /tmp)
#   TRUSTIFY_DUMP_URL      Base URL of the dumps (default: https://trustify-dumps.s3.eu-west-1.amazonaws.com)
#   TRUSTIFY_STORAGE_DIR   Storage directory of the backend (default: <repo>/.trustify/storage)

set -euo pipefail

FORCE=false
if [[ "${1:-}" == "-f" || "${1:-}" == "--force" ]]; then
    FORCE=true
    shift
fi

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 [-f|--force] <dump-id>" >&2
    exit 1
fi

DUMP_ID="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_URL="${TRUSTIFY_DUMP_URL:-https://trustify-dumps.s3.eu-west-1.amazonaws.com}"
DIR="${TRUSTIFY_DUMP_DIR:-${TMPDIR:-/tmp}}/${DUMP_ID}"
STORAGE="${TRUSTIFY_STORAGE_DIR:-${ROOT}/.trustify/storage}"

# expand a leading "~", which shells don't do in e.g. "env VAR=~/..."
DIR="${DIR/#\~/${HOME}}"
STORAGE="${STORAGE/#\~/${HOME}}"

compose() {
    podman compose -f "${ROOT}/etc/deploy/compose/compose.yaml" "$@"
}

psql_exec() {
    compose exec -T postgres psql -U postgres -v ON_ERROR_STOP=1 -q "$@"
}

# check the targets first, before downloading anything

TABLES=$(psql_exec -d trustify -tA -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
DB_IN_USE=false
if [[ "${TABLES}" != "0" ]]; then
    DB_IN_USE=true
fi

STORAGE_IN_USE=false
if [[ -e "${STORAGE}" ]]; then
    STORAGE_IN_USE=true
fi

if [[ "${FORCE}" != "true" ]]; then
    FAILED=false
    if [[ "${DB_IN_USE}" == "true" ]]; then
        echo "Database 'trustify' is not empty (${TABLES} tables)." >&2
        FAILED=true
    fi
    if [[ "${STORAGE_IN_USE}" == "true" ]]; then
        echo "Storage directory already exists: ${STORAGE}" >&2
        FAILED=true
    fi
    if [[ "${FAILED}" == "true" ]]; then
        echo "Re-run with -f/--force to drop and delete them." >&2
        exit 1
    fi
fi

# download, skipping files which are already present and valid

mkdir -p "${DIR}"
DIR="$(cd "${DIR}" && pwd)"
cd "${DIR}"

for f in dump.sql.xz dump.tar; do
    curl -fsSL -o "${f}.sha256" "${BASE_URL}/${DUMP_ID}/${f}.sha256"
    if [[ -f "${f}" ]] && sha256sum --quiet -c "${f}.sha256" 2>/dev/null; then
        echo "Already downloaded: ${DIR}/${f}"
        continue
    fi
    echo "Downloading: ${BASE_URL}/${DUMP_ID}/${f}"
    curl -fSL -C - -o "${f}" "${BASE_URL}/${DUMP_ID}/${f}"
    sha256sum -c "${f}.sha256"
done

# clean up, only once the download succeeded

if [[ "${DB_IN_USE}" == "true" ]]; then
    echo "Re-creating database 'trustify'"
    psql_exec -d postgres -c "DROP DATABASE trustify WITH (FORCE)"
    psql_exec -d postgres -c "CREATE DATABASE trustify"
fi

if [[ "${STORAGE_IN_USE}" == "true" ]]; then
    echo "Deleting storage directory: ${STORAGE}"
    rm -rf "${STORAGE}"
fi

# storage

mkdir -p "${STORAGE}"
echo "Extracting storage to: ${STORAGE}"
tar xf "${DIR}/dump.tar" -C "${STORAGE}"

# database

echo "Loading database (this takes a while)"
xz -dc "${DIR}/dump.sql.xz" | psql_exec -d trustify

echo "Done. Start the backend with: cargo run -p trustify-trustd -- api --devmode --embedded-oidc"
