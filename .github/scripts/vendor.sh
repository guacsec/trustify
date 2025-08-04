#!/usr/bin/env bash

# must be called from the root of the repository

set -e
set -x

VERSION=${1:-5.27.1}
shift || true
SHA256=${1:-15f1dc8c80663e5f2926818c1d8cf8ca5f97c4cbd494a90145c1e213d2c76dc3}
shift || true

cargo vendor > vendor.toml

curl -sSL "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v${VERSION}.zip" -o vendor/swagger-ui.zip

if [[ -n "$SHA256" ]]; then
  echo "$SHA256" vendor/swagger-ui.zip | sha256sum --check
fi

pushd vendor/trustify-ui/res
npm ci --ignore-scripts
popd
