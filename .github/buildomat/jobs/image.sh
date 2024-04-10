#!/bin/bash
#:
#: name = "image"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/out/*",
#: ]
#:
#: [[publish]]
#: series = "image"
#: name = "thundermuffin.tar.gz"
#: from_output = "/out/thundermuffin.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "thundermuffin.sha256.txt"
#: from_output = "/out/thundermuffin.sha256.txt"
#

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

banner build
ptime -m cargo build --release --verbose 

banner image
ptime -m cargo run -p thundermuffin-package

banner contents
tar tvfz out/thundermuffin.tar.gz

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
mv out/thundermuffin.tar.gz /out/thundermuffin.tar.gz

banner checksum
cd /out
digest -a sha256 thundermuffin.tar.gz > thundermuffin.sha256.txt

