#!/bin/bash

# run from the root dir: ".github/scripts/dev-build.sh 0.1.0-alpha.14"
# 13 as default in case we forget to pass the argument
VERSION=${1:-0.1.0-alpha.13}

TARGET="download"
SUB_DIR="trustd-x86_64-unknown-linux-gnu"
FULL_PATH="$TARGET/$SUB_DIR"

if [ ! -d "$FULL_PATH" ]; then
    mkdir -p "$FULL_PATH"
fi

FILE_NAME="trustd-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"

URL="https://github.com/guacsec/trustify/releases/download/v${VERSION}/${FILE_NAME}"

if [ ! -f "$FULL_PATH/$FILE_NAME" ]; then
    echo "Downloading $FILE_NAME ..."
    curl -L -o "$FULL_PATH/$FILE_NAME" "$URL"
fi

podman build --build-arg tag=${VERSION} -f .github/scripts/Containerfile .

