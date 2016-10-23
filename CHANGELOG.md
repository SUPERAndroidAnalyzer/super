# SUPER 0.2.0

- Features

 - Installation package for Mac OS

 - Line highlighting in found vulnerabilities

 - Reports now show the version of SUPER used to generate them

 - Added `--open` option to automatically open reports

- Bug Fixes

 - Changed paths for better multiplatform support

 - Regular Expressions
    - URL Disclosure no longer detects content providers ("content://...")

- Contributions

 - pocket7878
 - VoltBit
 - b52
 - nxnfufunezn
 - atk


# SUPER 0.1.0

- Features

 - Release of 64-bit packages for Linux (Debian 8.6, Ubuntu 16.04, CentOS 7, Fedora 24) and Windows (8.1+)

 - _AndroidManifest.xml_ analysis (Dangerous permission checks)

 - Certificate analysis (Certificate validity checks)

 - Code analysis (37 rules for checking the source code)
    - SQLi
    - XSS
    - URL Disclosure
    - Weak algorithms
    - Insecure WebViews
    - Generic exceptions
    - Root detection
    - ...

 - HTML and JSON report generation

 - Classification of vulnerabilities (Critical, High, Medium, Low, Info)

 - Application related info

 - File hashing
