# Changelog

## SUPER 0.3.1

### Bug Fixes

- SUPER will now have `super-analyzer` as package name. This avoids conflicts with Debian
  repositories.

## SUPER 0.3.0

### Features

- You can now specify the minimum criticality of a vulnerability for being reported. Using the
  `--min-criticality` CLI option, you can specify if the minimum reported criticality should be
  *warning*, *low*, *medium*, *high* or *critical*.
- Optional JSON and HTML reports: By default, SUPER will generate an HTML report, but no JSON
  report. This behaviour can be changed either by changing two configuration options in the
  *config.toml* file (`html_report` and `json_report`) or by invoking the script with `--json` or
  `--html` parameters. By default, if `--json` is used, the HTML report won't get generated, but if
  you want both, you can specify so by using both options: `--json --html`.
- Tab completions: If you now install SUPER using one of the provided packages for UNIX, you will
  get tab completions. So, anytime you don't exactly know the command, you can simply press TAB and
  you will get suggestions or even command completions. This works for Bash, Fish and ZSH.

### Internal Changes

- SUPER now requires Rust 1.15.1.
- Converted all `try!()` statements to use the new `?` Rust operator.
- Reduced cyclomatic complexity of Config::load_from_file() (#78): This makes configuration loading
  faster and easily maintainable.
- Improved logging using the `log` crate.
- Upgraded dependencies:
  - `clap`: 2.18 => **2.20**
  - `colored`: 1.3 => **1.4**
  - `serde`: 0.8 => **0.9**
  - `handlebars`: 0.22 => **0.25**
  - `chrono`: 0.2 => **0.3**
  - `regex`: 0.1 => **0.2**
  And some other minor upgrades. Both the `regex` and the `serde` dependencies have been the major
  upgrades and should improve our future releases.

### Changes in Rules

- Changed some regexes to match the new `regex` crate classes.
- The files to be searched with a given rule can now be filtered by two new fields:
  - `include_file_regex`: A regex that all tested files will match.
  - `exclude_file_regex`: A regex that will whitelist files matched by the previous regex.
  This enables much better file searching: If you need to search for `R` class variables, no need
  to search other files than `R.java`.

### Bug Fixes

- SUPER no longer prints to `stderr` on tests.
- Finally fixed all output coloring errors.

### Contributions

Apart from the core team, the following people has contributed to this release:
- **[@gnieto](https://github.com/gnieto)**

## SUPER 0.2.0

### Features

- SUPER now uses templates for report generation. This is one of the biggest changes of the
  release, and enables users to create their own report templates.
- Installation package for Mac OS.
- Line highlighting is now shown in the vulnerable line of the code in found vulnerabilities,
  colored depending on the criticality of the vulnerability.
- Reports now show the version of SUPER used to generate them.
- SUPER now supports analysis of applications placed anywhere instead of having to place them
  in a folder.
- Added the `--open` option to automatically open reports.
- Added the `--test-all` option to the CLI, that will test all *.apk* files in the *downloads*
  folder.
- Added options to the CLI to modify the properties in the config file. We now have
  `--downloads`, `--threads`, `--dist`, `--results`, `--apktool`, `--dex2jar`, `--jd-cmd`,
  `--rules` or `--template` options in the CLI.

### Changes in Rules

- SUPER now detects `exported` attributes in `<provider>`, `<receiver>`, `<activity>`,
  `<activity-alias>` and `<service>` tags in the *AndroidManifest.xml*, and reports potential
  vulnerabilities. This still needs work since we still don't have all the required information to
  show real vulnerabilities.

### Bug Fixes

- Changed paths for better multiplatform support.
- Regular Expressions:
  - URL Disclosure no longer detects content providers (`content://...`).
- Solved some coloring errors when combining styling and color in the same print.

### Contributions

Apart from the core team, the following people has contributed to this release:
- **[@pocket7878](https://github.com/pocket7878)**
- **[@VoltBit](https://github.com/VoltBit)**
- **[@b52](https://github.com/b52)**
- **[@nxnfufunezn](https://github.com/nxnfufunezn)**
- **[@atk](https://github.com/atk)**


## SUPER 0.1.0

### Features

- Release of 64-bit packages for Linux (Debian 8.6, Ubuntu 16.04, CentOS 7, Fedora 24) and Windows
  (8.1+).
- *AndroidManifest.xml* analysis (Dangerous permission checks).
- Certificate analysis (Certificate validity checks).
- Code analysis (37 rules for checking the source code):
  - SQLi
  - XSS
  - URL Disclosure
  - Weak algorithms
  - Insecure WebViews
  - Generic exceptions
  - Root detection
  - ...
- HTML and JSON report generation.
- Classification of vulnerabilities (Critical, High, Medium, Low, Info).
- Application related info.
- File fingerprinting.
