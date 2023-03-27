#!/bin/sh
set -e
# Needs aes_force_soft to make sure that no incompatible instructions are included in the image
RUSTFLAGS='-C panic=abort --cfg aes_force_soft' cargo b -p boot-rs --target x86_64-unknown-uefi "$@"