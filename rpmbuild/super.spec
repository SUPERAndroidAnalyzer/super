Name:    super
Version: 0.1.0
Release: 1%{?dist}
Summary: GNU Hello
URL:     http://superanalyzer.rocks/
License: GPLv3+
Source0: super-0.1.0.tar.gz
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
mkdir -p %{buildroot}%{_datadir}/%{name}/
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/
mkdir -p %{buildroot}%{_defaultdocdir}/%{name}/
install -p -m 755 target/release/%{name} %{buildroot}%{_bindir}/
install -p -m 644 -d vendor %{buildroot}%{_datadir}/%{name}/
install -p -m 644 rules.json %{buildroot}%{_sysconfdir}/%{name}/
install -p -m 644 config.toml %{buildroot}%{_sysconfdir}/%{name}/
install -p -m 644 config.toml.sample %{buildroot}%{_sysconfdir}/%{name}/
install -p -m 644 README.md %{buildroot}%{_defaultdocdir}/%{name}/

%files
%doc README.md
%license LICENSE
%{_bindir}/*
%{_datadir}/*
%config(noreplace) %{_sysconfdir}/%{name}/*

%changelog
