Name:    super-analyzer
Version: 0.4.1
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
~/.cargo/bin/rustup update

%build
~/.cargo/bin/cargo build --release

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_datadir}/bash-completion/completions
mkdir -p %{buildroot}%{_datadir}/fish/vendor_completions.d
mkdir -p %{buildroot}%{_datadir}/zsh/site-functions
mkdir -p %{buildroot}%{_datadir}/%{name}/templates/super/css
mkdir -p %{buildroot}%{_datadir}/%{name}/templates/super/img
mkdir -p %{buildroot}%{_datadir}/%{name}/templates/super/js
mkdir -p %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.1-SNAPSHOT/lib
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/
mkdir -p %{buildroot}%{_defaultdocdir}/%{name}/
install -p -d -m 755 %{buildroot}%{_datadir}/%{name}
install -p -m 755 target/release/super %{buildroot}%{_bindir}/
install -p -m 755 target/release/super.bash-completion %{buildroot}%{_datadir}/bash-completion/completions/
install -p -m 755 target/release/super.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/
install -p -m 755 target/release/_super %{buildroot}%{_datadir}/zsh/site-functions/
install -p -m 755 -D vendor/dex2jar-2.1-SNAPSHOT/lib/* %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.1-SNAPSHOT/lib/
install -p -m 755 -D vendor/dex2jar-2.1-SNAPSHOT/*.sh %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.1-SNAPSHOT/
install -p -m 644 -D vendor/dex2jar-2.1-SNAPSHOT/LICENSE.txt %{buildroot}%{_datadir}/%{name}/vendor/dex2jar-2.1-SNAPSHOT/
install -p -m 644 -D templates/super/css/* %{buildroot}%{_datadir}/%{name}/templates/super/css/
install -p -m 644 -D templates/super/img/* %{buildroot}%{_datadir}/%{name}/templates/super/img/
install -p -m 644 -D templates/super/js/* %{buildroot}%{_datadir}/%{name}/templates/super/js/
install -p -m 644 -D templates/super/*.hbs %{buildroot}%{_datadir}/%{name}/templates/super/
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
