#!/bin/bash

# Update the system
apt-get update -y &&
apt-get upgrade -y &&
apt-get dist-upgrade -y &&
apt-get autoremove -y &&

# Install build dependencies
apt-get install -y curl build-essential &&

# Install Rust
curl https://sh.rustup.rs -sSf | sh -s -- -y &&
source ~/.cargo/env &&

# Install cargo-deb
cargo install cargo-deb &&

# The tag won't be defined in a normal build.
if [[ $TAG == false ]]; then
  export TAG="0.4.1"; # TODO: change when bumping version.
fi &&

# Generate the .deb file
cd /root/super &&
cargo deb &&
mv target/debian/super-analyzer_`echo $TAG`_amd64.deb releases/super-analyzer_`echo $TAG`_ubuntu_amd64.deb