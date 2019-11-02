#!/bin/bash

# Create the package
cd /root &&
mkdir -vp super-analyzer-$TAG &&
cp -r super/* super-analyzer-$TAG/ &&
rm -fr super-analyzer-$TAG/target super-analyzer-$TAG/rpmbuild super-analyzer-$TAG/.git super-analyzer-$TAG/dist super-analyzer-$TAG/downloads super-analyzer-$TAG/results &&
tar -czvf /root/rpmbuild/SOURCES/$TAG.tar.gz super-analyzer-$TAG &&

# Build the RPM
cp /root/super/rpmbuild/super.spec /root/rpmbuild/SPECS/ &&
rpmbuild -v -bb /root/rpmbuild/SPECS/super.spec &&
mv /root/rpmbuild/RPMS/x86_64/super-analyzer-$TAG-1.el8.x86_64.rpm /root/super/releases/
