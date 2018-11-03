#!/bin/bash

action="$1"

if [ "$action" = "install_deps" ]; then
  # Install rustfmt and clippy.
  if [[ -z $PACKAGE && "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_RUST_VERSION" == "stable" ]]; then
    rustup component add rustfmt-preview clippy-preview
  fi

# Build the project with default features.
elif [ "$action" = "build" ]; then
  if [ -z $PACKAGE ]; then
    cargo build --verbose
  fi

# Package the crate for crates.io distribution.
elif [ "$action" = "package" ]; then
  if [ -z $PACKAGE ]; then
    cargo package --verbose
  fi

# Run unit and integration tests.
elif [ "$action" = "test" ]; then
  if [ -z $PACKAGE ]; then
    cargo test --verbose
  fi

# Run ignored unit and integration tests.
elif [ "$action" = "test_ignored" ]; then
  if [[ -z $PACKAGE && "$TRAVIS_RUST_VERSION" == "stable" && "$TRAVIS_OS_NAME" != "windows" ]]; then
    cargo test --verbose -- --ignored
  fi

# Build the project with unstable features.
elif [ "$action" = "build_unstable" ]; then
  if [[ -z $PACKAGE ]]; then
    cargo build --verbose --features unstable
  fi

# Run unit and integration tests with unstable features.
elif [ "$action" = "test_unstable" ]; then
  if [[ -z $PACKAGE && "$TRAVIS_RUST_VERSION" == "nightly" ]]; then
    cargo test --verbose --features unstable
  fi

# Run ignored unit and integration tests with unstable features.
elif [ "$action" = "test_unstable_ignored" ]; then
  if [[ -z $PACKAGE && "$TRAVIS_RUST_VERSION" == "nightly" ]]; then
    cargo test --verbose --features unstable -- --ignored
  fi


# Run Clippy.
elif [ "$action" = "clippy_run" ]; then
  if [[ -z $PACKAGE && "$TRAVIS_RUST_VERSION" == "stable" && "$TRAVIS_OS_NAME" == "linux" ]]; then
    cargo clippy --verbose
  fi

# Check formatting.
elif [ "$action" = "fmt_run" ]; then
  if [[ -z $PACKAGE && "$TRAVIS_RUST_VERSION" == "stable" && "$TRAVIS_OS_NAME" == "linux" ]]; then
      cargo fmt --verbose -- --check
  fi

# Upload code coverage report for stable builds in Linux.
elif [ "$action" = "upload_code_coverage" ]; then
  if [[ -z $PACKAGE && "$TRAVIS_RUST_VERSION" == "stable" && "$TRAVIS_OS_NAME" == "linux" ]]; then
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

# Upload development documentation for the develop branch.
elif [ "$action" = "upload_documentation" ]; then
  if [[ -z $PACKAGE && "$TRAVIS_RUST_VERSION" == "stable" && "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_PULL_REQUEST" = "false" && "$TRAVIS_BRANCH" == "develop" ]]; then
    cargo rustdoc -- --document-private-items &&
    echo "<meta http-equiv=refresh content=0;url=super/index.html>" > target/doc/index.html &&
    git clone https://github.com/davisp/ghp-import.git &&
    ./ghp-import/ghp_import.py -n -p -f -m "Documentation upload" -r https://"$GH_TOKEN"@github.com/"$TRAVIS_REPO_SLUG.git" target/doc &&
    echo "Uploaded documentation"
  fi

# Runs packaging tests for pull requests, new releases or release preparations in Ubuntu and Fedora.
elif [ "$action" = "dist_test" ]; then
  if ! [ -z $PACKAGE ]; then
    mkdir releases &&
    docker pull "$PACKAGE:latest" &&
    docker run -d -t -e TAG=$TAG -v $TRAVIS_BUILD_DIR:/root/super --name "$PACKAGE" --privileged "$PACKAGE:latest" "/bin/bash" &&
    docker exec "$PACKAGE" "/root/super/`echo $PACKAGE`_build.sh"
  fi

fi

exit $?
