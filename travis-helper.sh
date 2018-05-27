#!/bin/bash

action="$1"

if [ "$action" = "install_deps" ]; then
  # Install rustfmt.
  if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_RUST_VERSION" == "stable" ]]; then
    rustup component add rustfmt-preview
  fi

  # Install Clippy
  if [[ "$TRAVIS_RUST_VERSION" == "nightly" ]]; then
    cargo install clippy --force --verbose || true
  fi

elif [ "$action" = "clippy_run" ]; then
  if [ "$TRAVIS_RUST_VERSION" == "nightly" ] && cargo clippy --version; then
    cargo clippy --verbose
  fi

elif [ "$action" = "fmt_run" ]; then
  if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_RUST_VERSION" == "stable" ]]; then
      cargo fmt --verbose -- --write-mode=diff
  fi

elif [ "$action" = "upload_code_coverage" ]; then
  if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_RUST_VERSION" == "stable" ]]; then
    wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz &&
    tar xzf master.tar.gz &&
    cd kcov-master &&
    mkdir build &&
    cd build &&
    cmake .. &&
    make &&
    sudo make install &&
    cd ../.. &&
    rm -rf kcov-master &&
    for file in target/debug/super_analyzer*[^\.d]; do mkdir -p "target/cov/$(basename $file)"; kcov --exclude-pattern=/.cargo,/usr/lib --verify "target/cov/$(basename $file)" "$file"; done &&
    bash <(curl -s https://codecov.io/bash) &&
    echo "Uploaded code coverage"
  fi

elif [ "$action" = "upload_documentation" ]; then
  if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_RUST_VERSION" == "stable" && "$TRAVIS_PULL_REQUEST" = "false" && "$TRAVIS_BRANCH" == "develop" ]]; then
    cargo rustdoc -- --document-private-items &&
    echo "<meta http-equiv=refresh content=0;url=super/index.html>" > target/doc/index.html &&
    git clone https://github.com/davisp/ghp-import.git &&
    ./ghp-import/ghp_import.py -n -p -f -m "Documentation upload" -r https://"$GH_TOKEN"@github.com/"$TRAVIS_REPO_SLUG.git" target/doc &&
    echo "Uploaded documentation"
  fi

elif [ "$action" = "setup_docker" ]; then
  if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_RUST_VERSION" == "stable" ]]; then
    mkdir releases &&
    docker pull ubuntu:latest &&
    docker pull fedora:latest
  fi

elif [ "$action" = "dist_test" ]; then
  if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_RUST_VERSION" == "stable" ]]; then
    docker run -d -t -e TAG=$TRAVIS_TAG -v $TRAVIS_BUILD_DIR:/root/super --name "ubuntu" --privileged ubuntu:latest "/bin/bash" &&
    docker exec ubuntu /root/super/ubuntu_build.sh &&
    docker run -d -t -e TAG=$TRAVIS_TAG -v $TRAVIS_BUILD_DIR:/root/super --name "fedora" --privileged fedora:latest "/bin/bash" &&
    docker exec fedora /root/super/fedora_build.sh
  fi

elif [ "$action" = "before_deploy" ]; then
  docker pull debian:latest &&
  docker pull centos:latest &&
  docker run -d -t -e TAG=$TRAVIS_TAG -v $TRAVIS_BUILD_DIR:/root/super --name "debian" --privileged debian:latest "/bin/bash" &&
  docker exec debian /root/super/debian_build.sh &&
  docker run -d -t -e TAG=$TRAVIS_TAG -v $TRAVIS_BUILD_DIR:/root/super --name "centos" --privileged centos:latest "/bin/bash" &&
  docker exec centos /root/super/centos_build.sh
fi

exit $?
