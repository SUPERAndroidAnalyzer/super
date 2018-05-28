#!/bin/bash

# Update the system
yum upgrade -y &&
yum autoremove -y &&

# Install build dependencies
yum install -y wget gcc make rpm-build redhat-rpm-config &&

# Create needed directories and macros
mkdir -p /root/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS} &&
echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros &&

# Create the package
cd /root &&
mkdir super-analyzer-$TAG &&
cp -r super/* super-analyzer-$TAG/ &&
rm -fr super-analyzer-$TAG/target super-analyzer-$TAG/rpmbuild super-analyzer-$TAG/.git super-analyzer-$TAG/dist super-analyzer-$TAG/downloads super-analyzer-$TAG/results &&
tar -czvf /root/rpmbuild/SOURCES/$TAG.tar.gz super-analyzer-$TAG &&

# Build the RPM
cp /root/super/rpmbuild/super.spec /root/rpmbuild/SPECS/ &&
rpmbuild -v -bb /root/rpmbuild/SPECS/super.spec &&
mv /root/rpmbuild/RPMS/x86_64/super-analyzer-$TAG-1.el7.x86_64.rpm /root/super/releases/
