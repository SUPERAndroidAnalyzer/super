#!/bin/bash

# Update the system
apt-get update -y &&
apt-get upgrade -y &&
apt-get dist-upgrade -y &&
apt-get autoremove -y &&

# Install build dependencies
apt-get install -y curl build-essential dpkg libc-bin liblzma-dev &&

# Install Rust
curl https://sh.rustup.rs -sSf | sh -s -- -y &&
source ~/.cargo/env &&

# Install cargo-deb
cargo install cargo-deb &&

# Generate the .deb file
cd /root/super &&
cargo deb -v &&
mv target/debian/super-analyzer_`echo $TAG`_amd64.deb releases/super-analyzer_`echo $TAG`_debian_amd64.deb
