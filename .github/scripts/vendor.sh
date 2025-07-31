#!/usr/bin/env bash

# must be called from the root of the repository

set -e
set -x

VERSION=${1:-5.27.0}
shift || true

cargo vendor > vendor.toml

curl -sSL "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v${VERSION}.zip" -o vendor/swagger-ui.zip

pushd vendor/trustify-ui/res
npm ci --ignore-scripts
popd
