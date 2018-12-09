#!/bin/bash

# Generate the .deb file
cd /root/super &&
cargo deb -v &&
mv target/debian/super-analyzer_`echo $TAG`_amd64.deb releases/super-analyzer_`echo $TAG`_ubuntu_amd64.deb
