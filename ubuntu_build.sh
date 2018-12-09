#!/bin/bash

source ~/.cargo/env &&
cd /root/super &&

# Generate the .deb file
cargo deb -v &&
mv target/debian/super-analyzer_`echo $TAG`_amd64.deb releases/super-analyzer_`echo $TAG`_ubuntu_amd64.deb
