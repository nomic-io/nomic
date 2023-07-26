#!/bin/bash

echo "Building legacy nomic at $OUT_DIR/nomic..."
git clone https://github.com/nomic-io/nomic.git $OUT_DIR/nomic
cd $OUT_DIR/nomic
git checkout .
git checkout $NOMIC_LEGACY_REV
git pull

rustc --version
cargo build --release
NOMIC_LEGACY_PATH=$OUT_DIR/nomic/target/release/nomic
echo "cargo:rustc-env=NOMIC_LEGACY_PATH=$NOMIC_LEGACY_PATH"
echo "cargo:rustc-env=NOMIC_LEGACY_VERSION=$($NOMIC_LEGACY_PATH --version)"
