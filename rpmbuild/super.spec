Name:    super
Version: 0.1.0
Release: 1%{?dist}
Summary: GNU Hello
URL:     http://superanalyzer.rocks/
License: GPLv3+
Source0: super-0.1.0.tar.gz

%description
Secure, Unified, Powerful and Extensible Rust Android Analyzer.

%prep
%autosetup
/usr/bin/curl https://sh.rustup.rs -sSf | sh -s -- -y

%build
~/.cargo/bin/cargo build --release --verbose

%install
mkdir -p %{buildroot}/%{_bindir}

%files

%changelog
