# SUPER Android Analyzer #

[![Build Status][linux_mac_build_img]][linux_mac_build]
[![Build status][windows_build_img]][windows_build]
[![codecov][coverage_img]][coverage]

<img src="templates/super/img/logo.png" alt="SUPER Android Analyzer logo" title="SUPER Android Analyzer" width="150">

*Secure, Unified, Powerful and Extensible Rust Android Analyzer*

SUPER is a command-line application that can be used in Windows, MacOS X and Linux, that analyzes
*.apk* files in search for vulnerabilities. It does this by decompressing APKs and applying a series
of rules to detect those vulnerabilities.

But, why create a new analyzer? Is it not enough with MobSF, Qark, Androbugs…? Well, we think it's
not enough. All of them have two main issues we wanted to fix: They are written in Java or Python
and they are not easily extensible. They are not meant to be used by businesses directly working in
Android analysis, and don't put that kind of functionality first.

Our approach solves those issues in different ways: We first decided to use **Rust** as our
programming language. The language developed openly by Mozilla Foundation gives us lots of
utilities to work with regular expressions, files etc. and, most importantly, it enables us to
create a secure software that does not depend in *JVM* or *JIT* compilers. With Rust, stack
overflows, segmentation faults etc. are directly not possible, which makes sense in a security
centered application. And it also gives us enough power to do efficient analysis, giving us the
option to automate it in high volume. This is given by Rust zero-cost abstractions, that gives us
an efficiency only comparable to C/C++.

And secondly, we decided to make the software 100% extensible: All rules are centered in a
`rules.json` file, and each company or tester could create its own rules to analyze what they need.
It's also modular, so that new developments can easily add new functionality. Finally, a templating
system for results reports gives users the ability to personalize the report.

It also gives great code review tools, directly in the HTML report, so that anyone can search
through the generated code with syntax highlighting for even better vulnerability analysis.

## Installation ##

We have released some binaries in the [download page][downloads] for Windows (8.1+), Linux, and
MacOS X. We only have 64-bit packages for now. If you need to use SUPER in a 32-bit system, you
will need to [compile SUPER from source][compile]. For that, you will need to install **Rust** with
[rustup.rs][rustup].

*Note: It requires Java 1.7+ to run.*

## Usage ##

SUPER is very easy to use. Just download the desired *.apk* into the *downloads* folder (create
that folder if necessary) and use the name as an argument when running the program. After the
execution, a detailed report will appear in the *results* folder with that application name. There
are a few usage options available:

```
USAGE:
    super [FLAGS] [OPTIONS] <package>

FLAGS:
        --bench       Show benchmarks for the analysis
        --force       If you'd like to force the auditor to do everything from the beginning
    -h, --help        Prints help information
        --html        Generates the reults in HTML format
        --json        Generates the reults in JSON format
        --open        Open the report in a browser once it is complete
    -q, --quiet       If you'd like a zen auditor that won't output anything in stdout
    -a, --test-all    Test all .apk files in the downloads directory
    -V, --version     Prints version information
    -v, --verbose     If you'd like the auditor to talk more than necessary

OPTIONS:
        --apktool <apktool>                    Path to the apktool file
        --dex2jar <dex2jar>                    Where to store the jar files
        --dist <dist>                          Folder where distribution files will be extracted
        --downloads <downloads>                Folder where the downloads are stored
        --jd-cmd <jd-cmd>                      Path to the jd-cmd file
        --min-criticality <min_criticality>    Set a minimum criticality to analyze (Critical, High, Medium, Low)
        --results <results>                    Folder where to store the results
        --rules <rules>                        Path to a JSON rules file
        --template <template>                  Path to a results template file
    -t, --threads <threads>                    Number of threads to use

ARGS:
    <package>    The package string of the application to test
```

## Contributing ##

Everybody is welcome to contribute to SUPER. Please check out the
[SUPER Contribution Guidelines][contributing] for instructions about how to proceed.

## License ##

This program is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

[linux_mac_build_img]: https://travis-ci.org/SUPERAndroidAnalyzer/super.svg?branch=develop
[linux_mac_build]: https://travis-ci.org/SUPERAndroidAnalyzer/super
[windows_build_img]: https://ci.appveyor.com/api/projects/status/7xuikqyne4a2jn7e/branch/develop?svg=true
[windows_build]: https://ci.appveyor.com/project/Razican/super/branch/develop
[coverage_img]: https://codecov.io/gh/SUPERAndroidAnalyzer/super/branch/develop/graph/badge.svg
[coverage]: https://codecov.io/gh/SUPERAndroidAnalyzer/super
[compile]: http://superanalyzer.rocks/download.html#compile-from-source
[downloads]: http://superanalyzer.rocks/download.html
[rustup]: https://www.rustup.rs/
[contributing]: https://github.com/SUPERAndroidAnalyzer/super/blob/master/contributing.md
