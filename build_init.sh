#!/bin/sh
set -e
RUSTFLAGS='-C panic=abort -C link-arg=-nostartfiles -C target-cpu=native' cargo b -p initramfs-rs --target x86_64-unknown-linux-gnu "$@"
