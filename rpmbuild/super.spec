Name:    super
Version: 0.1.0
Release: 1%{?dist}
Summary: Secure, Unified, Powerful and Extensible Rust Android Analyzer.
URL:     http://superanalyzer.rocks/
License: GPLv3+

Source0: https://github.com/SUPERAndroidAnalyzer/super/archive/%{version}.tar.gz
Requires: java-1.8.0-openjdk-headless, openssl

%description
Secure, Unified, Powerful and Extensible Rust Android Analyzer.

%prep
%autosetup
/usr/bin/curl https://sh.rustup.rs -sSf | sh -s -- -y

%build
~/.cargo/bin/cargo build --release

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_datadir}/%{name}/vendor/results_template/css
mkdir -p %{buildroot}%{_datadir}/%{name}/vendor/results_template/img
mkdir -p %{buildroot}%{_datadir}/%{name}/vendor/results_template/js
mkdir -p %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.0/lib
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/
mkdir -p %{buildroot}%{_defaultdocdir}/%{name}/
install -p -d -m 755 %{buildroot}%{_datadir}/%{name}
install -p -m 755 target/release/%{name} %{buildroot}%{_bindir}/
install -p -m 755 -D vendor/dex2jar-2.0/lib/* %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.0/lib/
install -p -m 755 -D vendor/dex2jar-2.0/*.sh %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.0/
install -p -m 644 -D vendor/dex2jar-2.0/LICENSE.txt %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.0/
install -p -m 644 -D vendor/results_template/css/* %{buildroot}%{_datadir}/%{name}/vendor/results_template/css/
install -p -m 644 -D vendor/results_template/img/* %{buildroot}%{_datadir}/%{name}/vendor/results_template/img/
install -p -m 644 -D vendor/results_template/js/* %{buildroot}%{_datadir}/%{name}/vendor/results_template/js/
install -p -m 755 -D vendor/*.jar %{buildroot}%{_datadir}/%{name}/vendor/
install -p -m 644 -D vendor/*.txt %{buildroot}%{_datadir}/%{name}/vendor/
install -p -m 644 rules.json %{buildroot}%{_sysconfdir}/%{name}/
install -p -m 644 config.toml %{buildroot}%{_sysconfdir}/%{name}/
install -p -m 644 config.toml.sample %{buildroot}%{_sysconfdir}/%{name}/
install -p -m 644 README.md %{buildroot}%{_defaultdocdir}/%{name}/

%files
%doc README.md
%license LICENSE
%{_bindir}/*
%{_datadir}/*
%config(noreplace) %{_sysconfdir}/*

%changelog
