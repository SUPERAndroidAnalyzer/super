#!/bin/bash

# Update the system
dnf upgrade --refresh -y &&
dnf autoremove -y &&

# Install build dependencies
dnf install -y wget gcc fedora-packager &&

# Create the package
cd /root &&
mkdir -v super-analyzer-$TAG &&
cp -r super/* super-analyzer-$TAG/ &&
rm -fr super-analyzer-$TAG/target super-analyzer-$TAG/rpmbuild super-analyzer-$TAG/.git super-analyzer-$TAG/dist super-analyzer-$TAG/downloads super-analyzer-$TAG/results &&
tar -czvf super/rpmbuild/$TAG.tar.gz super-analyzer-$TAG &&

# Build the RPM
cd /root/super/rpmbuild &&
fedpkg -v --release f28 local &&
mv x86_64/super-analyzer-$TAG-1.fc28.x86_64.rpm ../releases/
