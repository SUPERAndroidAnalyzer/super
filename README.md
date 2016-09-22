# SUPER Android Analyzer #

[![Build Status](https://travis-ci.org/SUPERAndroidAnalyzer/super.svg?branch=develop)](https://travis-ci.org/SUPERAndroidAnalyzer/super)
[![Build status](https://ci.appveyor.com/api/projects/status/7xuikqyne4a2jn7e?svg=true)](https://ci.appveyor.com/project/Razican/super)
[![Coverage Status](https://coveralls.io/repos/github/SUPERAndroidAnalyzer/super/badge.svg?branch=develop)](https://coveralls.io/github/SUPERAndroidAnalyzer/super?branch=develop)

<img src="src/super.jpg" alt="SUPER Android Analyzer logo" title="SUPER Android Analyzer" width="150">

Secure, Unified, Powerful and Extensible Rust Android Analyzer

This project aims to create an automatic system capable of analyzing **Android** applications to search for security vulnerabilities. In the process of creating such tool the current market will be analyzed to look into the existent solutions and find out what can be improved. Also, a vulnerability analysis process will be researched, choosing the one that best matches with the original objectives to design our tool later.

The second objective of the project will be to implement the developed tool in a way that it will be capable of analyzing a significant amount of applications. During this process new knowledge will be acquired both in technology and security, with will provide us with the bases for new developments.

The main objective of the project will be to analyze a big amount of **Android** applications from the **Google Play** market carrying out a global analysis of the current state of the security in **Android** applications. Furthermore, our applications could be used in the future to make an analysis of the evolution of said state.

## Installation ##

We are planning on releasing binaries for the application so it is easier to use. Until then, installing **Rust** is needed to use it. These are the steps before using the program:

1. Download and install **Rust**. This is easily done through the following link:

   https://www.rustup.rs/

2. Clone the repository.

  `git clone https://github.com/SUPERAndroidAnalyzer/super.git`

3. Build dependencies. Inside the repository, execute the following command. It should download and compile all program dependencies.

  `cargo build`

If everything went right up until this point, you're ready to go!

*Note: It requires Java 1.7+ and OpenSSL*

## Usage ##

SUPER is very easy to use. Just download the desired *.apk* into the *downloads* folder (create that folder if necessary) and use the name as an argument when running the program. After the execution, a detailed report will appear in the *results* folder with that application name. There are a few usage options available:

```
USAGE:
    super [FLAGS] <package>

FLAGS:
        --bench      Show benchmarks for the analysis.
        --force      If you'd like to force the auditor to do everything from the beginning.
    -h, --help       Prints help information
    -q, --quiet      If you'd like a zen auditor that won't talk unless it's 100% necessary.
    -V, --version    Prints version information
    -v, --verbose    If you'd like the auditor to talk more than necessary.

ARGS:
    <package>    The package string of the application to test.
```

## Contributing ##

Everybody is welcome to contribute to SUPER. Please check out the [SUPER Contribution Guidelines](https://github.com/SUPERAndroidAnalyzer/super/blob/develop/contributing.md)
for instructions about how to proceed.

## License ##

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
