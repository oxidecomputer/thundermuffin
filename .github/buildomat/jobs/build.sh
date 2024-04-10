#!/bin/bash
#:
#: name = "build"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
#: ]
#:
#: [[publish]]
#: series = "release"
#: name = "thundermuffin"
#: from_output = "/work/release/thundermuffin"
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

banner "check"
cargo fmt -- --check
cargo clippy --all-targets -- --deny warnings

banner "build"
ptime -m cargo build
ptime -m cargo build --release

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/thundermuffin /work/$x/thundermuffin
done
