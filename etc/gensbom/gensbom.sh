#!/bin/bash

set -euo pipefail

WORKSPACE="${PWD}"
SYFT_COMMAND="syft"

if [[ ! -t 0 || ! -t 1 || ! -t 2 ]]; then
    export NO_COLOR=1
fi

if [[ "${NO_COLOR:-0}" =~ ^(n|no|0|f|false)$ ]]; then
    _BOLD="$(echo -ne '\e[1m')"
    _RED="$(echo -ne '\e[31m')"
    _BROWN="$(echo -ne '\e[33m')"
    _VIOLET="$(echo -ne '\e[35m')"
    _AZURE="$(echo -ne '\e[36m')"
    _YELLOW="$(echo -ne '\e[93m')"
    _RESET="$(echo -ne '\e[0m')"
    _Q1="${_VIOLET}"
    _Q0="${_RESET}"
else
    _BOLD=""
    _RED=""
    _BROWN=""
    _VIOLET=""
    _AZURE=""
    _YELLOW=""
    _RESET=""
    _Q1="\`"
    _Q0="\`"
fi

function inform() {
    echo "$0: $*"
}

function warning() {
    echo "${_YELLOW}WARNING[$0]: $*${_RESET}" >&2
}

function error() {
    echo "${_RED}ERROR[$0]: $*${_RESET}" >&2
    exit 1
}

function usage() {
    cat <<-__EOF__
	Usage: ${_AZURE}$0 <FILE>${_RESET}

	or as the container:

	  ${_BROWN}# Read a list of images from the <FILE>${_RESET}
	  ${_AZURE}podman run --rm -v "\${PWD}":/gensbom:Z -e 'TPA_*' gensbom:latest <FILE>${_RESET}

	In the current working directory:

	  1. Read the list of images (one image per line) from ${_VIOLET}<FILE>${_RESET}.
	  2. For every image from the list:
	       * generate an SBOM in CycloneDX 1.6 format using Syft
	       * ingest the SBOM to the Trusted Profile Analyzer (TPA)
	  3. The ${_Q1}sboms${_Q0} directory and the ${_Q1}sboms.zip${_Q0} archive contain the
	     generated SBOMs.

	${_YELLOW}WARNING:${_RESET} The ${_Q1}sboms${_Q0} directory and the ${_Q1}sboms.zip${_Q0} archive from the
	         previous run will be removed!

	${_BOLD}Authentication${_RESET}

	  ${_VIOLET}config.json${_RESET}
	    A file with the valid container registry credentials following the
	    Docker format. This file must be in the current working directory

	  ${_VIOLET}TPA_AUTH_TOKEN${_RESET}
	    Authorization token for TPA

	${_BOLD}Environment variables${_RESET}

	  ${_VIOLET}TPA_SERVICE_URL${_RESET}
	    URL with running TPA instance

	  ${_VIOLET}TPA_AUTH_TOKEN${_RESET}
	    Valid authorization token for TPA. Required if the TPA instance
	    requires authorization

	${_BOLD}See also${_RESET}

	  ${_VIOLET}config.json${_RESET} format
	    https://github.com/google/go-containerregistry/tree/main/pkg/authn#docker-config-auth
	    https://github.com/anchore/syft/wiki/private-registry-authentication

	__EOF__
}

if [[ -z "${1:-}" ]]; then
    usage
    exit 0
fi

_INPUT="$1"

if [[ ! -f "${_INPUT}" ]]; then
    error "\`${_INPUT}\` is not a file"
fi

if [[ -z "${TPA_SERVICE_URL:-}" ]]; then
    error "TPA_SERVICE_URL environment variable is not set or it is empty"
fi

_DOCKER_CONFIG="${WORKSPACE}/config.json"

if [[ ! -f "${_DOCKER_CONFIG}" ]]; then
    warning "Docker configuration with credentials (\`${_DOCKER_CONFIG}\`) not present"
    warning "Syft will not be able to access private container registries"
else
    export DOCKER_CONFIG="${WORKSPACE}"
fi

_AUTH_HEADER="Authorization: ${TPA_AUTH_TOKEN:-}"

if [[ -z "${TPA_AUTH_TOKEN:-}" ]]; then
    warning "TPA_AUTH_TOKEN environment variable is not set or it is empty"
    warning "Authorized communication with ${TPA_SERVICE_URL} will not be possible"
    _AUTH_HEADER=""
fi

_SBOMS_DIR="${WORKSPACE}/sboms"
_SBOMS_ARCHIVE="sboms.zip"

rm -rf "${_SBOMS_DIR}" "${WORKSPACE}/${_SBOMS_ARCHIVE}"
mkdir -p "${_SBOMS_DIR}"

_SBOM_COUNTER=0

while IFS="" read -r _IMAGE || [[ -n "${_IMAGE}" ]]; do
    if [[ -z "${_IMAGE}" ]]; then
        continue
    fi

    _SBOM="${_SBOMS_DIR}/$(printf 'sbom%010d' "${_SBOM_COUNTER}")-$(echo "${_IMAGE}" | tr '/:' '--').json"
    _SBOM_COUNTER=$(( _SBOM_COUNTER + 1 ))

    if ! "${SYFT_COMMAND}" -v scan "${_IMAGE}" -o "cyclonedx-json=${_SBOM}"; then
        # Remove empty/corrupted file so it will not be included in the final archive
        rm -f "${_SBOM}"
        continue
    fi

    if [[ ! -s "${_SBOM}" ]]; then
        warning "File \`${_SBOM}\` was not created"
        # Remove empty file so it will not be included in the final archive
        rm -f "${_SBOM}"
        continue
    fi

    _SHA512="sha512:$(sha512sum "${_SBOM}" | awk '{print $1}')"
    inform "File ${_Q1}${_SBOM}${_Q0} with ${_Q1}${_SHA512}${_Q0} has been created"

    if curl -sSfL \
        ${_AUTH_HEADER:+-H "${_AUTH_HEADER}"} \
        "${TPA_SERVICE_URL}/api/v2/sbom/${_SHA512}/download" \
        >/dev/null 2>&1; \
    then
        # Do not ingest already ingested SBOM
        inform "File ${_Q1}${_SBOM}${_Q0} is already ingested"
        continue
    fi

    if ! curl -sSfL \
        -X POST \
        ${_AUTH_HEADER:+-H "${_AUTH_HEADER}"} \
        -H "Content-Type: application/json" \
        -d "@${_SBOM}" \
        "${TPA_SERVICE_URL}/api/v2/sbom"; \
    then
        warning "Failed to ingest \`${_SBOM}\`"
    else
        # Put few newlines after the `curl` output
        echo -ne '\n\n'
    fi
done < "${_INPUT}"

pushd "${_SBOMS_DIR}" >/dev/null

if find -name '*.json' -type f | grep -q .; then
    find -name '*.json' -type f -print | zip "${_SBOMS_ARCHIVE}" -@
    mv "${_SBOMS_ARCHIVE}" "../${_SBOMS_ARCHIVE}"
fi

popd >/dev/null
