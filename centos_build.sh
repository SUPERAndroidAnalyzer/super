#!/bin/bash

# Update the system
yum upgrade -y &&
yum autoremove -y &&

# Install build dependencies
yum install -y wget gcc make rpm-build redhat-rpm-config &&

# Create needed directories and macros
mkdir -p /root/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS} &&
echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros &&

# Download the package
cd /root/rpmbuild/SOURCES &&
wget https://github.com/SUPERAndroidAnalyzer/super/archive/$TAG.tar.gz &&

# We need to rename the contained folder from super-X.Y.Z to super-analyzer-X.Y.Z
tar -xzvf $TAG.tar.gz &&
mv super-$TAG super-analyzer-$TAG &&
rm $TAG.tar.gz &&
tar -czvf $TAG.tar.gz super-analyzer-$TAG &&
rm -fr super-analyzer-$TAG &&

# Build the RPM
cp /root/super/rpmbuild/super.spec /root/rpmbuild/SPECS/ &&
rpmbuild -v -bb /root/rpmbuild/SPECS/super.spec &&
mv /root/rpmbuild/RPMS/x86_64/super-analyzer-$TAG-1.el7.x86_64.rpm /root/super/releases/
