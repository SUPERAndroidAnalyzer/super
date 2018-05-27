#!/bin/bash

# Update the system.
apt-get update &&
apt-get upgrade &&
apt-get dist-upgrade &&
apt-get autoremove;

# Install Rust
curl https://sh.rustup.rs -sSf | sh -s -- -y &&
source ~/.cargo/env

# Install cargo-deb
cargo install cargo-deb

# Generate the .deb file
cd /root/super &&
cargo deb &&
for file in target/debian/*.deb; do
    mv "$file" `echo "$file" | sed -e 's/_amd64/_ubuntu_amd64/g'`;
done &&
mv target/debian/*.deb releases/