#!/bin/bash

action="$1"

if [ "$action" = "install_deps" ]; then
  if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_RUST_VERSION" == "stable" ]]; then
    # Install rustfmt
    cargo install rustfmt --force --verbose &&

    # Install cargo-deb
    # Using the git version since the release has bugs
    cargo install --git https://github.com/mmstick/cargo-deb.git --force --verbose
  fi

  # Install clippy
  if [[ "$TRAVIS_RUST_VERSION" == "nightly" ]]; then
    cargo install clippy --force --verbose
  fi

elif [ "$action" = "clippy_run" ]; then
  if [ "$TRAVIS_RUST_VERSION" == "nightly" ] && cargo clippy --version; then
    cargo clippy --verbose
  fi

elif [ "$action" = "dep_run" ]; then
  if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_RUST_VERSION" == "stable" ]]; then
    cargo deb --verbose
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
    mkdir -p "target/cov/super-analyzer"; kcov --exclude-pattern=/.cargo,/usr/lib --verify "target/cov/super-analyzer" "super-analyzer" &&
    for file in target/debug/super_analyzer*[^\.d]; do mkdir -p "target/cov/$(basename $file)"; kcov --exclude-pattern=/.cargo,/usr/lib --verify "target/cov/$(basename $file)" "$file"; done &&
    bash <(curl -s https://codecov.io/bash) &&
    echo "Uploaded code coverage"
  fi

elif [ "$action" = "upload_documentation" ]; then
  if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_RUST_VERSION" == "stable" && "$TRAVIS_PULL_REQUEST" = "false" && "$TRAVIS_BRANCH" == "develop" ]]; then
    cargo doc &&
    echo "<meta http-equiv=refresh content=0;url=super/index.html>" > target/doc/index.html &&
    git clone https://github.com/davisp/ghp-import.git &&
    ./ghp-import/ghp_import.py -n -p -f -m "Documentation upload" -r https://"$GH_TOKEN"@github.com/"$TRAVIS_REPO_SLUG.git" target/doc &&
    echo "Uploaded documentation"
  fi

fi

exit $?
