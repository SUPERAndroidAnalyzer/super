#!/bin/bash

# Update the system
dnf upgrade --refresh -y &&
dnf autoremove -y &&

# Install build dependencies
dnf install -y wget gcc fedora-packager &&

# Download the package
cd /root/super/rpmbuild &&
(($TAG && wget https://github.com/SUPERAndroidAnalyzer/super/archive/$TAG.tar.gz) ||
  # The tag won't be defined in a normal build, we create a .tar.gz package
  (cd /root &&
  TAG="0.4.1" && # TODO: change when bumping version.
  mkdir super-$TAG &&
  cp -r super/* super-$TAG/ &&
  rm -fr super-$TAG/target super-$TAG/rpmbuild super-$TAG/.git super-$TAG/dist super-$TAG/downloads super-$TAG/results &&
  tar -czvf super/rpmbuild/$TAG.tar.gz super-$TAG &&
  cd /root/super/rpmbuild)
) &&

# The tag won't be defined in a normal build.
if [[ $TAG == false ]]; then
  export TAG="0.4.1"; # TODO: change when bumping version.
fi &&

# We need to rename the contained folder from super-X.Y.Z to super-analyzer-X.Y.Z
tar -xzvf $TAG.tar.gz &&
mv super-$TAG super-analyzer-$TAG &&
rm $TAG.tar.gz &&
tar -czvf $TAG.tar.gz super-analyzer-$TAG &&
rm -fr super-analyzer-$TAG &&

# Build the RPM
fedpkg --release f28 local &&
mv x86_64/*.rpm ../releases/