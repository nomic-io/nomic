#!/bin/bash

set -e

BUILD_DIR=$OUT_DIR/nomic
NOMIC_LEGACY_PATH=$OUT_DIR/nomic-$NOMIC_LEGACY_REV

if [ ! -f "$NOMIC_LEGACY_PATH" ]; then
    echo "Building legacy nomic at $NOMIC_LEGACY_PATH..."
    if [ ! -d "$BUILD_DIR" ]; then
        git clone https://github.com/nomic-io/nomic.git $BUILD_DIR
    fi
    cd $BUILD_DIR
    git checkout .
    git checkout main
    git pull
    git checkout $NOMIC_LEGACY_REV
    git fetch

    rustc --version
    echo "Building with features: $CARGO_FEATURES"
    cargo build --release --no-default-features --features $CARGO_FEATURES
    cp $BUILD_DIR/target/release/nomic $NOMIC_LEGACY_PATH
else
    echo "Skipping legacy nomic binary build (already exists at $NOMIC_LEGACY_PATH)" 
fi

if [[ ! -z "${NOMIC_CLEANUP_LEGACY_BUILD}" ]]; then
    rm -rf $BUILD_DIR
fi

echo "cargo:rustc-env=NOMIC_LEGACY_BUILD_PATH=$NOMIC_LEGACY_PATH"
echo "cargo:rustc-env=NOMIC_LEGACY_BUILD_VERSION=$($NOMIC_LEGACY_PATH --version)"
