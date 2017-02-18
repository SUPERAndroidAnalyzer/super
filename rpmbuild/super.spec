Name:    super-analyzer
Version: 0.4.0
Release: 1%{?dist}
Summary: Secure, Unified, Powerful and Extensible Rust Android Analyzer.
URL:     http://superanalyzer.rocks/
License: GPLv3+

Source0: https://github.com/SUPERAndroidAnalyzer/super/archive/%{version}.tar.gz
Requires: java-1.8.0-openjdk-headless, bash

%description
Secure, Unified, Powerful and Extensible Rust Android Analyzer.

%prep
%autosetup
/usr/bin/curl https://sh.rustup.rs -sSf | sh -s -- -y

%build
~/.cargo/bin/cargo build --release

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_datadir}/bash-completion/completions
mkdir -p %{buildroot}%{_datadir}/fish/vendor_completions.d
mkdir -p %{buildroot}%{_datadir}/zsh/site-functions
mkdir -p %{buildroot}%{_datadir}/%{name}/templates/%{name}/css
mkdir -p %{buildroot}%{_datadir}/%{name}/templates/%{name}/img
mkdir -p %{buildroot}%{_datadir}/%{name}/templates/%{name}/js
mkdir -p %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.1-SNAPSHOT/lib
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/
mkdir -p %{buildroot}%{_defaultdocdir}/%{name}/
install -p -d -m 755 %{buildroot}%{_datadir}/%{name}
install -p -m 755 target/release/%{name} %{buildroot}%{_bindir}/
install -p -m 755 target/release/%{name}.bash-completion %{buildroot}%{_datadir}/bash-completion/completions/
install -p -m 755 target/release/%{name}.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/
install -p -m 755 target/release/_%{name} %{buildroot}%{_datadir}/zsh/site-functions/
install -p -m 755 -D vendor/dex2jar-2.1-SNAPSHOT/lib/* %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.1-SNAPSHOT/lib/
install -p -m 755 -D vendor/dex2jar-2.1-SNAPSHOT/*.sh %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.1-SNAPSHOT/
install -p -m 644 -D vendor/dex2jar-2.1-SNAPSHOT/LICENSE.txt %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.1-SNAPSHOT/
install -p -m 644 -D templates/%{name}/css/* %{buildroot}%{_datadir}/%{name}/templates/%{name}/css/
install -p -m 644 -D templates/%{name}/img/* %{buildroot}%{_datadir}/%{name}/templates/%{name}/img/
install -p -m 644 -D templates/%{name}/js/* %{buildroot}%{_datadir}/%{name}/templates/%{name}/js/
install -p -m 644 -D templates/%{name}/*.hbs %{buildroot}%{_datadir}/%{name}/templates/%{name}/
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
