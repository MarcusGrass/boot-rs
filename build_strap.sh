#!/bin/sh
set -e
RUSTFLAGS='-C panic=abort -C link-arg=-nostartfiles -C target-cpu=native -C target-feature=+crt-static -C relocation-model=static' cargo b -p boot-strap --target x86_64-unknown-linux-gnu "$@"