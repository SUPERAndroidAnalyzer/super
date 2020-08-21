//! Module containing the manifest analysis logic.

mod permission;
mod permission_checklist;
#[cfg(test)]
mod tests;

use crate::{
    criticality::Criticality,
    get_code, get_string, print_vulnerability, print_warning,
    results::{Results, Vulnerability},
    Config,
};
use anyhow::{bail, Context, Error, Result};
use colored::Colorize;
pub use permission::Permission;
pub use permission_checklist::PermissionChecklist;
use quick_xml::{
    events::{attributes::Attributes, Event},
    Reader,
};
use std::{
    convert::TryFrom,
    fs,
    path::Path,
    str::{self, FromStr},
};

/// Performs the manifest analysis.
pub fn analysis<S: AsRef<str>>(
    config: &Config,
    package: S,
    results: &mut Results,
) -> Option<Manifest> {
    if config.is_verbose() {
        println!(
            "Loading the manifest file. For this, we first parse the document and then we'll \
             analyze it."
        )
    }

    let manifest = match Manifest::load(
        config.dist_folder().join(package.as_ref()),
        config,
        package.as_ref(),
        results,
    ) {
        Ok(m) => {
            if config.is_verbose() {
                println!("{}", "The manifest was loaded successfully!".green());
                println!();
            }
            m
        }
        Err(e) => {
            print_warning(format!(
                "There was an error when loading the manifest: {}",
                e
            ));
            if config.is_verbose() {
                println!(
                    "The rest of the analysis will continue, but there will be no analysis of the \
                     AndroidManifest.xml file, and code analysis rules requiring permissions will \
                     not run."
                );
            }
            return None;
        }
    };

    if manifest.package() != package.as_ref() {
        print_warning(format!(
            "Seems that the package in the AndroidManifest.xml is not the same as the application \
             ID provided. Provided application id: {}, manifest package: {}",
            package.as_ref(),
            manifest.package()
        ));

        if config.is_verbose() {
            println!(
                "This does not mean that something went wrong, but it's supposed to have the \
                 application in the format {{package}}.apk in the {} folder and use the package \
                 as the application ID for this auditor.",
                "downloads".italic()
            );
        }
    }

    results.set_app_package(manifest.package());
    results.set_app_label(manifest.label());
    results.set_app_description(manifest.description());
    results.set_app_version(manifest.version_str());
    results.set_app_version_num(manifest.version_number());
    results.set_app_min_sdk(manifest.min_sdk());
    if manifest.target_sdk().is_some() {
        results.set_app_target_sdk(manifest.target_sdk().unwrap());
    }

    if manifest.is_debug() {
        let criticality = Criticality::Critical;

        if criticality >= config.min_criticality() {
            let description = "The application is in debug mode. This allows any malicious person \
                               to inject arbitrary code in the application. This option should \
                               only be used while in development.";

            let line = get_line(manifest.code(), "android:debuggable=\"true\"");
            let code = line.map(|l| get_code(manifest.code(), l, l));

            let vulnerability = Vulnerability::new(
                criticality,
                "Manifest Debug",
                description,
                Some("AndroidManifest.xml"),
                line,
                line,
                code,
            );

            results.add_vulnerability(vulnerability);
            print_vulnerability(description, criticality);
        }
    }

    if manifest.needs_large_heap() {
        let criticality = Criticality::Warning;

        if criticality >= config.min_criticality() {
            let description = "The application needs a large heap. This is not a vulnerability as \
                               such, but could be in devices with small heap. Check if the large \
                               heap is actually needed.";

            let line = get_line(manifest.code(), "android:largeHeap=\"true\"");
            let code = line.map(|l| get_code(manifest.code(), l, l));

            let vulnerability = Vulnerability::new(
                criticality,
                "Large heap",
                description,
                Some("AndroidManifest.xml"),
                line,
                line,
                code,
            );
            results.add_vulnerability(vulnerability);
            print_vulnerability(description, criticality);
        }
    }

    if manifest.allows_backup() {
        let criticality = Criticality::Medium;

        if criticality >= config.min_criticality() {
            let description = "This option allows backups of the application data via adb. \
                               Malicious people with physical access could use adb to get private \
                               data of your app into their PC.";

            let line = get_line(manifest.code(), "android:allowBackup=\"true\"");
            let code = line.map(|l| get_code(manifest.code(), l, l));

            let vulnerability = Vulnerability::new(
                criticality,
                "Allows Backup",
                description,
                Some("AndroidManifest.xml"),
                line,
                line,
                code,
            );
            results.add_vulnerability(vulnerability);
            print_vulnerability(description, criticality);
        }
    }

    for permission in config.permissions() {
        if manifest
            .permission_checklist()
            .needs_permission(permission.name())
            && permission.criticality() >= config.min_criticality()
        {
            let line = get_line(manifest.code(), permission.name().as_str());
            let code = line.map(|l| get_code(manifest.code(), l, l));

            let vulnerability = Vulnerability::new(
                permission.criticality(),
                permission.label(),
                permission.description(),
                Some("AndroidManifest.xml"),
                line,
                line,
                code,
            );
            results.add_vulnerability(vulnerability);
            print_vulnerability(permission.description(), permission.criticality());
        }
    }

    if config.is_verbose() {
        println!();
        println!("{}", "The manifest was analyzed correctly!".green());
        println!();
    } else if !config.is_quiet() {
        println!("Manifest analyzed.");
    }

    Some(manifest)
}

/// Manifest analysis representation structure.
#[derive(Debug, Default)]
pub struct Manifest {
    code: String,
    package: String,
    label: String,
    description: String,
    allows_backup: bool,
    has_code: bool,
    large_heap: bool,
    install_location: InstallLocation,
    permissions: PermissionChecklist,
    debug: bool,
    min_sdk: u32,
    target_sdk: Option<u32>,
    version_number: u32,
    version_str: String,
}

impl Manifest {
    /// Loads the given manifest in memory and analyzes it.
    pub fn load<P: AsRef<Path>, S: AsRef<str>>(
        path: P,
        config: &Config,
        package: S,
        results: &mut Results,
    ) -> Result<Self> {
        let code = fs::read_to_string(path.as_ref().join("AndroidManifest.xml"))?;
        let mut manifest = Self::default();

        manifest.set_code(code.as_str());

        let bytes = code.into_bytes();
        let mut parser = Reader::from_reader(bytes.as_slice());
        let _ = parser.trim_text(true);
        let mut buf = Vec::new();

        loop {
            match parser.read_event(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    if let Err(e) = match e.name() {
                        b"manifest" => manifest.parse_manifest_attributes(e.attributes()),
                        b"uses-sdk" => manifest.parse_sdk_attributes(e.attributes()),
                        b"application" => manifest.parse_application_attributes(
                            e.attributes(),
                            config,
                            package.as_ref(),
                        ),
                        b"uses-permission" => {
                            manifest.parse_permission_attributes(e.attributes(), config, results)
                        }
                        tag @ b"provider"
                        | tag @ b"receiver"
                        | tag @ b"activity"
                        | tag @ b"activity-alias"
                        | tag @ b"service" => manifest.check_exported_attributes(
                            str::from_utf8(tag).unwrap(),
                            e.attributes(),
                            config,
                            results,
                        ),
                        _ => continue,
                    } {
                        print_warning(format!(
                            "An error occurred when parsing the `AndroidManifest.xml` file: \
                             {}.\nThe process will continue, though.",
                            e
                        ));
                    };
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(e) => {
                    print_warning(format!(
                        "An error occurred when parsing the `AndroidManifest.xml` file: {}.\n
                         The process will continue, though.",
                        e
                    ));
                }
            }
        }

        Ok(manifest)
    }

    fn parse_manifest_attributes(&mut self, attributes: Attributes<'_>) -> Result<()> {
        for attr in attributes {
            let attr = attr?;

            match attr.key.split(|b| b == &b':').last() {
                Some(b"package") => self.set_package(
                    str::from_utf8(&attr.value).context("invalid UTF-8 for attribute value")?,
                ),
                Some(b"versionCode") => {
                    let version_number = str::from_utf8(&attr.value)
                        .context("invalid UTF-8 for attribute value")?
                        .parse::<u32>()
                        .map_err(|e| {
                            print_warning(format!(
                                "An error occurred when parsing the version in the manifest: \
                                 {}.\nThe process will continue, though.",
                                e
                            ));
                            e
                        })?;
                    self.set_version_number(version_number);
                }
                Some(b"versionName") => self.set_version_str(
                    str::from_utf8(&attr.value).context("invalid UTF-8 for attribute value")?,
                ),
                Some(b"installLocation") => {
                    let location = InstallLocation::try_from(attr.value.as_ref()).map_err(|e| {
                        print_warning(format!(
                            "An error occurred when parsing the `installLocation` attribute in \
                             the manifest: {}.\nThe process will continue, though.",
                            e
                        ));
                        e
                    })?;
                    self.set_install_location(location)
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn parse_sdk_attributes(&mut self, attributes: Attributes<'_>) -> Result<()> {
        for attr in attributes {
            let attr = attr?;

            match attr.key.split(|b| b == &b':').last() {
                Some(b"minSdkVersion") => self.set_min_sdk(
                    str::from_utf8(&attr.value)
                        .context("invalid UTF-8 for attribute value")?
                        .parse::<u32>()
                        .map_err(|e| {
                            print_warning(format!(
                                "An error occurred when parsing the `minSdkVersion` attribute in \
                                 the manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                            e
                        })?,
                ),
                Some(b"targetSdkVersion") => self.set_target_sdk(
                    str::from_utf8(&attr.value)
                        .context("invalid UTF-8 for attribute value")?
                        .parse::<u32>()
                        .map_err(|e| {
                            print_warning(format!(
                                "An error occurred when parsing the `targetSdkVersion` attribute \
                                 in the manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                            e
                        })?,
                ),
                _ => {}
            }
        }

        Ok(())
    }

    fn parse_application_attributes<S>(
        &mut self,
        attributes: Attributes<'_>,
        config: &Config,
        package: S,
    ) -> Result<()>
    where
        S: AsRef<str>,
    {
        for attr in attributes {
            let attr = attr?;

            match attr.key.split(|b| b == &b':').last() {
                Some(b"debuggable") => {
                    if let Ok(true) = str::from_utf8(&attr.value)
                        .context("invalid UTF-8 for attribute value")?
                        .parse::<bool>()
                        .map_err(|e| {
                            print_warning(format!(
                                "An error occurred when parsing the `debuggable` attribute in the \
                                 manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                        })
                    {
                        self.set_debug();
                    }
                }
                Some(b"allowBackup") => {
                    if let Ok(true) = str::from_utf8(&attr.value)
                        .context("invalid UTF-8 for attribute value")?
                        .parse::<bool>()
                        .map_err(|e| {
                            print_warning(format!(
                                "An error occurred when parsing the `allowBackup` attribute in \
                                 the manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                        })
                    {
                        self.set_allows_backup();
                    }
                }
                Some(b"description") => self.set_description(
                    str::from_utf8(&attr.value).context("invalid UTF-8 for attribute value")?,
                ),
                Some(b"hasCode") => {
                    if let Ok(true) = str::from_utf8(&attr.value)
                        .context("invalid UTF-8 for attribute value")?
                        .parse::<bool>()
                        .map_err(|e| {
                            print_warning(format!(
                                "An error occurred when parsing the `hasCode` attribute in the \
                                 manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                        })
                    {
                        self.set_has_code();
                    }
                }
                Some(b"largeHeap") => {
                    if let Ok(true) = str::from_utf8(&attr.value)
                        .context("invalid UTF-8 for attribute value")?
                        .parse::<bool>()
                        .map_err(|e| {
                            print_warning(format!(
                                "An error occurred when parsing the `largeHeap` attribute in the \
                                 manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                        })
                    {
                        self.set_large_heap();
                    }
                }
                Some(b"label") => {
                    if attr.value.starts_with(b"@string/") {
                        if let Ok(Some(label)) =
                            get_string(&attr.value[8..], config, package.as_ref()).map_err(|e| {
                                print_warning(format!(
                                    "An error occurred when trying to get the string for the app \
                                     label in the manifest: {}.\nThe process will continue, \
                                     though.",
                                    e
                                ));
                            })
                        {
                            self.set_label(label)
                        }
                    } else if let Ok(label) = str::from_utf8(&attr.value).map_err(|e| {
                        print_warning(format!(
                            "An error occurred when trying to get the string for the app label in \
                             the manifest: {}.\nThe process will continue, though.",
                            e
                        ));
                    }) {
                        self.set_label(label);
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn parse_permission_attributes(
        &mut self,
        attributes: Attributes<'_>,
        config: &Config,
        results: &mut Results,
    ) -> Result<()> {
        for attr in attributes {
            let attr = attr?;
            if let Some(b"name") = attr.key.split(|b| b == &b':').last() {
                let permission = if let Ok(p) = Permission::try_from(attr.value.as_ref()) {
                    p
                } else if let Ok(value) = str::from_utf8(&attr.value).map_err(|e| {
                    print_warning(format!(
                        "An error occurred when trying to get the string for the permission name \
                         in the manifest: {}.\nThe process will continue, though.",
                        e
                    ));
                }) {
                    let line = get_line(self.code(), value);
                    let code = line.map(|l| get_code(self.code(), l, l));

                    let criticality = config.unknown_permission_criticality();
                    let description = config.unknown_permission_description();
                    let file = Some("AndroidManifest.xml");

                    if criticality > config.min_criticality() {
                        let vulnerability = Vulnerability::new(
                            criticality,
                            "Unknown permission",
                            description,
                            file,
                            line,
                            line,
                            code,
                        );
                        results.add_vulnerability(vulnerability);

                        print_vulnerability(description, criticality);
                    }
                    break;
                } else {
                    break;
                };
                self.permissions.set_needs_permission(permission);
            }
        }
        Ok(())
    }

    fn check_exported_attributes(
        &mut self,
        tag: &str,
        attributes: Attributes<'_>,
        config: &Config,
        results: &mut Results,
    ) -> Result<()> {
        {
            let mut exported = None;
            let mut name = String::new();
            for attr in attributes {
                let attr = attr?;
                match attr.key.split(|b| b == &b':').last() {
                    Some(b"exported") => {
                        if let Ok(Ok(found_exported)) = str::from_utf8(&attr.value)
                            .map_err(|e| {
                                print_warning(format!(
                                    "An error occurred when trying to get the string for the \
                                     `exported` in the manifest: {}.\nThe process will continue, \
                                     though.",
                                    e
                                ));
                            })
                            .map(|s| {
                                s.parse::<bool>().map_err(|e| {
                                    print_warning(format!(
                                        "An error occurred when trying to get the string for the \
                                         `exported` in the manifest: {}.\nThe process will \
                                         continue, though.",
                                        e
                                    ));
                                })
                            })
                        {
                            exported = Some(found_exported);
                        }
                    }
                    Some(b"name") => {
                        if let Ok(s) = str::from_utf8(&attr.value)
                            .map_err(|e| {
                                print_warning(format!(
                                    "An error occurred when trying to get the string for the \
                                     `exported` in the manifest: {}.\nThe process will continue, \
                                     though.",
                                    e
                                ));
                            })
                            .map(str::to_owned)
                        {
                            name = s
                        }
                    }
                    _ => {}
                }
            }
            match exported {
                Some(true) | None => {
                    if tag != "provider" || exported.is_some() || self.min_sdk() < 17 {
                        let line = get_line(self.code(), &format!("android:name=\"{}\"", name));
                        let code = line.map(|l| get_code(self.code(), l, l));

                        let criticality = Criticality::Warning;

                        if criticality >= config.min_criticality() {
                            let vulnerability = Vulnerability::new(
                                criticality,
                                format!("Exported {}", tag),
                                format!(
                                    "Exported {} was found. It can be used by other applications.",
                                    tag
                                ),
                                Some("AndroidManifest.xml"),
                                line,
                                line,
                                code,
                            );
                            results.add_vulnerability(vulnerability);

                            print_vulnerability(
                                format!(
                                    "Exported {} was found. It can be used by other applications.",
                                    tag
                                ),
                                Criticality::Warning,
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn set_code<S: Into<String>>(&mut self, code: S) {
        self.code = code.into();
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn package(&self) -> &str {
        &self.package
    }

    fn set_package<S: Into<String>>(&mut self, package: S) {
        self.package = package.into();
    }

    pub fn version_number(&self) -> u32 {
        self.version_number
    }

    fn set_version_number(&mut self, version_number: u32) {
        self.version_number = version_number;
    }

    pub fn version_str(&self) -> &str {
        &self.version_str
    }

    fn set_version_str<S: Into<String>>(&mut self, version_str: S) {
        self.version_str = version_str.into();
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    fn set_label<S: Into<String>>(&mut self, label: S) {
        self.label = label.into();
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    fn set_description<S: Into<String>>(&mut self, description: S) {
        self.description = description.into();
    }

    pub fn min_sdk(&self) -> u32 {
        self.min_sdk
    }

    pub fn set_min_sdk(&mut self, min_sdk: u32) {
        self.min_sdk = min_sdk;
    }

    pub fn target_sdk(&self) -> Option<u32> {
        self.target_sdk
    }

    pub fn set_target_sdk(&mut self, target_sdk: u32) {
        self.target_sdk = Some(target_sdk);
    }

    fn set_has_code(&mut self) {
        self.has_code = true;
    }

    pub fn allows_backup(&self) -> bool {
        self.allows_backup
    }

    fn set_allows_backup(&mut self) {
        self.allows_backup = true;
    }

    pub fn needs_large_heap(&self) -> bool {
        self.large_heap
    }

    fn set_large_heap(&mut self) {
        self.large_heap = true;
    }

    fn set_install_location(&mut self, install_location: InstallLocation) {
        self.install_location = install_location;
    }

    pub fn is_debug(&self) -> bool {
        self.debug
    }

    fn set_debug(&mut self) {
        self.debug = true;
    }

    pub fn permission_checklist(&self) -> &PermissionChecklist {
        &self.permissions
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstallLocation {
    InternalOnly,
    Auto,
    PreferExternal,
}

impl Default for InstallLocation {
    fn default() -> Self {
        Self::InternalOnly
    }
}

impl TryFrom<&[u8]> for InstallLocation {
    type Error = Error;

    fn try_from(slc: &[u8]) -> Result<Self> {
        match slc {
            b"internalOnly" => Ok(Self::InternalOnly),
            b"auto" => Ok(Self::Auto),
            b"preferExternal" => Ok(Self::PreferExternal),
            _ => bail!(
                "invalid install location {}",
                str::from_utf8(slc).context("invalid UTF-8 install location")?
            ),
        }
    }
}

impl FromStr for InstallLocation {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::try_from(s.as_bytes())
    }
}

/// Gets the line number of the `haystack` in the `code`, if it contains it.
fn get_line(code: &str, haystack: &str) -> Option<usize> {
    code.lines().enumerate().find_map(|(i, line)| {
        if line.contains(haystack) {
            Some(i)
        } else {
            None
        }
    })
}
