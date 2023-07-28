#!/bin/bash

BUILD_DIR=$OUT_DIR/nomic
echo "Building legacy nomic at $BUILD_DIR..."
if [ ! -d "$BUILD_DIR" ]; then
    git clone https://github.com/nomic-io/nomic.git $OUT_DIR/nomic
fi
cd $BUILD_DIR
git checkout .
git checkout main
git pull
git checkout $NOMIC_LEGACY_REV

rustc --version
cargo build --release
NOMIC_LEGACY_PATH=$OUT_DIR/nomic/target/release/nomic
echo "cargo:rustc-env=NOMIC_LEGACY_PATH=$NOMIC_LEGACY_PATH"
echo "cargo:rustc-env=NOMIC_LEGACY_VERSION=$($NOMIC_LEGACY_PATH --version)"
