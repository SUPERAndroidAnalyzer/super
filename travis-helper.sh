#!/bin/bash

action="$1"
package="$2"

# Run unit and integration tests.
if [ "$action" = "test" ]; then
  cargo test --verbose

# Run ignored unit and integration tests.
elif [ "$action" = "test_ignored" ]; then
  if [[ "$TRAVIS_RUST_VERSION" == "stable" &&
        "$TRAVIS_OS_NAME" != "windows" &&
        (-n "$TRAVIS_TAG") ]]; then
    cargo test --verbose -- --ignored
  fi

# Run unit and integration tests with unstable features.
elif [ "$action" = "test_unstable" ]; then
    cargo test --verbose --features unstable &&
    cargo test --verbose --features unstable -- --ignored

# Check formatting.
elif [ "$action" = "fmt_check" ]; then
  if [[ "$TRAVIS_RUST_VERSION" == "stable" && "$TRAVIS_OS_NAME" == "linux" ]]; then
    rustup component add rustfmt &&
    cargo fmt --verbose -- --check
  fi

# Run Clippy.
elif [ "$action" = "clippy_check" ]; then
  if [[ "$TRAVIS_RUST_VERSION" == "stable" && "$TRAVIS_OS_NAME" == "linux" ]]; then
    rustup component add clippy &&
    cargo clippy --verbose
  fi

# Upload code coverage report for stable builds in Linux.
elif [ "$action" = "upload_code_coverage" ]; then
  if [[ "$TRAVIS_BUILD_STAGE_NAME" == "Test" &&
        "$TRAVIS_RUST_VERSION" == "stable" &&
        "$TRAVIS_OS_NAME" == "linux" &&
        "$TRAVIS_JOB_NAME" != *"packaging"* ]]; then
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
    for file in target/debug/super_analyzer*[^\.d]; do
      mkdir -p "target/cov/$(basename $file)";
      kcov --exclude-pattern=/.cargo,/usr/lib --verify "target/cov/$(basename $file)" "$file";
    done &&
    bash <(curl -s https://codecov.io/bash) &&
    echo "Uploaded code coverage"
  fi

# Upload development documentation for the develop branch.
elif [ "$action" = "documentation" ]; then
  if [ "$TRAVIS_BRANCH" = "develop" ]; then
    cargo doc -v --document-private-items &&
    echo "<meta http-equiv=refresh content=0;url=super/index.html>" > target/doc/index.html
  fi

# Runs packaging tests for pull requests, new releases or release preparations in Ubuntu and Fedora.
elif [ "$action" = "dist_test" ]; then
    mkdir -pv releases &&
    docker pull "$package:latest" &&
    docker run -d -t -e TAG=$TAG -v $TRAVIS_BUILD_DIR:/root/super --name "$package" --privileged "$package:latest" "/bin/bash" &&
    docker exec "$package" "/root/super/`echo $package`_build.sh"

elif [ "action" = "deploy"]; then
  if [[ -v TRAVIS_TAG ]]; then
    mkdir -pv releases &&
    for PACKAGE in "debian" "ubuntu" "fedora" "centos"; do
      docker pull "$PACKAGE:latest" &&
      docker run -d -t -e TAG=$TAG -v $TRAVIS_BUILD_DIR:/root/super --name "$PACKAGE" --privileged "$PACKAGE:latest" "/bin/bash" &&
      docker exec "$PACKAGE" "/root/super/`echo $PACKAGE`_build.sh"
    done
  fi

fi
exit $?
