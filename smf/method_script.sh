#!/bin/bash

set -o errexit
set -o pipefail

export RUST_LOG=info

args=(
    --port "$(svcprop -c -p config/port "${SMF_FMRI}")"
)

if [[ -e /opt/oxide/thundermuffin/bin/thundermuffin ]];
then
    # mgd.tar.gz gets the binaries at /opt/oxide/mgd/bin/
    exec /opt/oxide/thundermuffin/bin/thundermuffin run "${args[@]}"
else
    exit 1
fi
