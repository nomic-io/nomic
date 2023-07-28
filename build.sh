#!/bin/bash

set -e

BUILD_DIR=$OUT_DIR/nomic
NOMIC_LEGACY_PATH=$OUT_DIR/nomic-$NOMIC_LEGACY_REV

if [ ! -f "$NOMIC_LEGACY_PATH" ]; then
    echo "Building legacy nomic at $BUILD_DIR..."
    if [ ! -d "$BUILD_DIR" ]; then
        git clone https://github.com/nomic-io/nomic.git $BUILD_DIR
    fi
    cd $BUILD_DIR
    git checkout .
    git checkout main
    git pull
    git checkout $NOMIC_LEGACY_REV

    rustc --version
    cargo build --release
    mv $BUILD_DIR/target/release/nomic $NOMIC_LEGACY_PATH
else
    echo "Skipping legacy nomic binary build (already exists at $NOMIC_LEGACY_PATH)" 
fi

rm -rf $BUILD_DIR

echo "cargo:rustc-env=NOMIC_LEGACY_BUILD_PATH=$NOMIC_LEGACY_PATH"
echo "cargo:rustc-env=NOMIC_LEGACY_BUILD_VERSION=$($NOMIC_LEGACY_PATH --version)"
