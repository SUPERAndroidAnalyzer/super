//! Module containing the manifest analysis logic.

use std::{fs, path::Path, str::FromStr};

use colored::Colorize;
use failure::Error;
use serde::{self, Deserialize, Deserializer};
use xml::{
    attribute::OwnedAttribute,
    reader::{EventReader, XmlEvent},
};

use crate::{
    criticality::Criticality,
    get_code, get_string, print_vulnerability, print_warning,
    results::{Results, Vulnerability},
    Config, ErrorKind, PARSER_CONFIG,
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
                 application in the format {{package}}.apk in the {} folder and use the package as \
                 the application ID for this auditor.",
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

            let line = get_line(manifest.code(), "android:debuggable=\"true\"").ok();
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

            let line = get_line(manifest.code(), "android:largeHeap=\"true\"").ok();
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

            let line = get_line(manifest.code(), "android:allowBackup=\"true\"").ok();
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
            let line = get_line(manifest.code(), permission.name().as_str()).ok();
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
    ) -> Result<Self, Error> {
        let code = fs::read_to_string(path.as_ref().join("AndroidManifest.xml"))?;
        let mut manifest = Self::default();

        manifest.set_code(code.as_str());

        let bytes = code.into_bytes();
        let parser = EventReader::new_with_config(bytes.as_slice(), PARSER_CONFIG.clone());

        for e in parser {
            match e {
                Ok(XmlEvent::StartElement {
                    name, attributes, ..
                }) => match name.local_name.as_str() {
                    "manifest" => manifest.parse_manifest_attributes(attributes),
                    "uses-sdk" => manifest.parse_sdk_attributes(attributes),
                    "application" => {
                        manifest.parse_application_attributes(attributes, config, package.as_ref())
                    }
                    "uses-permission" => {
                        manifest.parse_permission_attributes(attributes, config, results)
                    }
                    tag @ "provider"
                    | tag @ "receiver"
                    | tag @ "activity"
                    | tag @ "activity-alias"
                    | tag @ "service" => {
                        manifest.check_exported_attributes(tag, attributes, config, results)
                    }
                    _ => {}
                },
                Ok(_) => {}
                Err(e) => {
                    print_warning(format!(
                        "An error occurred when parsing the `AndroidManifest.xml` file: {}.\nThe \
                         process will continue, though.",
                        e
                    ));
                }
            }
        }

        Ok(manifest)
    }

    fn parse_manifest_attributes<A>(&mut self, attributes: A)
    where
        A: IntoIterator<Item = OwnedAttribute>,
    {
        for attr in attributes {
            match attr.name.local_name.as_str() {
                "package" => self.set_package(attr.value.as_str()),
                "versionCode" => {
                    let version_number: u32 = match attr.value.parse() {
                        Ok(n) => n,
                        Err(e) => {
                            print_warning(format!(
                                "An error occurred when parsing the version in the manifest: {}.\
                                 \nThe process will continue, though.",
                                e
                            ));
                            break;
                        }
                    };
                    self.set_version_number(version_number);
                }
                "versionName" => self.set_version_str(attr.value.as_str()),
                "installLocation" => {
                    let location = match InstallLocation::from_str(attr.value.as_str()) {
                        Ok(l) => l,
                        Err(e) => {
                            print_warning(format!(
                                "An error occurred when parsing the `installLocation` attribute \
                                 in the manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                            break;
                        }
                    };
                    self.set_install_location(location)
                }
                _ => {}
            }
        }
    }

    fn parse_sdk_attributes<A>(&mut self, attributes: A)
    where
        A: IntoIterator<Item = OwnedAttribute>,
    {
        for attr in attributes {
            match attr.name.local_name.as_str() {
                "minSdkVersion" => {
                    let min_sdk_version: u32 = match attr.value.as_str().parse() {
                        Ok(m) => m,
                        Err(e) => {
                            print_warning(format!(
                                "An error occurred when parsing the `minSdkVersion` attribute in \
                                 the manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                            break;
                        }
                    };
                    self.set_min_sdk(min_sdk_version);
                }
                "targetSdkVersion" => {
                    let target_sdk_version: u32 = match attr.value.as_str().parse() {
                        Ok(t) => t,
                        Err(e) => {
                            print_warning(format!(
                                "An error occurred when parsing the `targetSdkVersion` attribute \
                                 in the manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                            break;
                        }
                    };
                    self.set_target_sdk(target_sdk_version);
                }
                _ => {}
            }
        }
    }

    fn parse_application_attributes<A, S>(&mut self, attributes: A, config: &Config, package: S)
    where
        A: IntoIterator<Item = OwnedAttribute>,
        S: AsRef<str>,
    {
        for attr in attributes {
            match attr.name.local_name.as_str() {
                "debuggable" => {
                    let debug: bool = match attr.value.as_str().parse() {
                        Ok(b) => b,
                        Err(e) => {
                            print_warning(format!(
                                "An error occurred when parsing the `debuggable` attribute in \
                                 the manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                            break;
                        }
                    };
                    if debug {
                        self.set_debug();
                    }
                }
                "allowBackup" => {
                    let allows_backup: bool = match attr.value.as_str().parse() {
                        Ok(b) => b,
                        Err(e) => {
                            print_warning(format!(
                                "An error occurred when parsing the `allowBackup` attribute in \
                                 the manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                            break;
                        }
                    };
                    if allows_backup {
                        self.set_allows_backup();
                    }
                }
                "description" => self.set_description(attr.value.as_str()),
                "hasCode" => {
                    let has_code: bool = match attr.value.as_str().parse() {
                        Ok(b) => b,
                        Err(e) => {
                            print_warning(format!(
                                "An error occurred when parsing the `hasCode` attribute in the \
                                 manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                            break;
                        }
                    };
                    if has_code {
                        self.set_has_code();
                    }
                }
                "largeHeap" => {
                    let large_heap: bool = match attr.value.as_str().parse() {
                        Ok(b) => b,
                        Err(e) => {
                            print_warning(format!(
                                "An error occurred when parsing the `largeHeap` attribute in the \
                                 manifest: {}.\nThe process will continue, though.",
                                e
                            ));
                            break;
                        }
                    };
                    if large_heap {
                        self.set_large_heap();
                    }
                }
                "label" => self.set_label(
                    if attr.value.starts_with("@string/") {
                        match get_string(&attr.value[8..], config, package.as_ref()) {
                            Ok(s) => s,
                            Err(e) => {
                                print_warning(format!(
                                    "An error occurred when trying to get the string for the app \
                                     label in the manifest: {}.\nThe process will continue, though.",
                                    e
                                ));
                                break;
                            }
                        }
                    } else {
                        attr.value
                    }.as_str(),
                ),
                _ => {}
            }
        }
    }

    fn parse_permission_attributes<A>(
        &mut self,
        attributes: A,
        config: &Config,
        results: &mut Results,
    ) where
        A: IntoIterator<Item = OwnedAttribute>,
    {
        for attr in attributes {
            if let "name" = attr.name.local_name.as_str() {
                let permission = if let Ok(p) = Permission::from_str(attr.value.as_str()) {
                    p
                } else {
                    let line = get_line(self.code(), attr.value.as_str()).ok();
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
                };
                self.permissions.set_needs_permission(permission);
            }
        }
    }

    fn check_exported_attributes<A>(
        &mut self,
        tag: &str,
        attributes: A,
        config: &Config,
        results: &mut Results,
    ) where
        A: IntoIterator<Item = OwnedAttribute>,
    {
        {
            let mut exported = None;
            let mut name = String::new();
            for attr in attributes {
                match attr.name.local_name.as_str() {
                    "exported" => {
                        if let Ok(found_exported) = attr.value.as_str().parse() {
                            exported = Some(found_exported);
                        }
                    }
                    "name" => name = attr.value,
                    _ => {}
                }
            }
            match exported {
                Some(true) | None => {
                    if tag != "provider" || exported.is_some() || self.min_sdk() < 17 {
                        let line =
                            get_line(self.code(), &format!("android:name=\"{}\"", name)).ok();
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

impl FromStr for InstallLocation {
    type Err = ErrorKind;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "internalOnly" => Ok(Self::InternalOnly),
            "auto" => Ok(Self::Auto),
            "preferExternal" => Ok(Self::PreferExternal),
            _ => Err(ErrorKind::Parse),
        }
    }
}

fn get_line<S: AsRef<str>>(code: S, haystack: S) -> Result<usize, ErrorKind> {
    for (i, line) in code.as_ref().lines().enumerate() {
        if line.contains(haystack.as_ref()) {
            return Ok(i);
        }
    }

    Err(ErrorKind::CodeNotFound)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{get_line, InstallLocation, Permission, PermissionChecklist};

    #[test]
    fn it_get_line() {
        let code1 = "Hello, I'm Razican.
        I'm trying to create a complex code to test
        multi-line code search. This should be
        enough, probably.";

        let code2 = "Hello, I'm Razican.
        I'm trying to create a complex code to test
        multi-line code
        search. This should be
        enough, probably.";

        let code3 = "Hello, I'm Razican.I'm trying to create a complex
        code to test
        multi-line code search. This should be
        enough, probably.";

        assert_eq!(get_line(code1, "Razican").unwrap(), 0);
        assert_eq!(get_line(code1, "multi-line").unwrap(), 2);
        assert_eq!(get_line(code2, "search").unwrap(), 3);
        assert_eq!(get_line(code2, "probably").unwrap(), 4);
        assert_eq!(get_line(code3, "create").unwrap(), 0);
        assert_eq!(get_line(code3, "enough").unwrap(), 3);
        assert!(get_line(code3, "non-matching").is_err());
    }

    #[test]
    fn it_install_loc_from_str() {
        assert_eq!(
            InstallLocation::InternalOnly,
            InstallLocation::from_str("internalOnly").unwrap()
        );
        assert_eq!(
            InstallLocation::Auto,
            InstallLocation::from_str("auto").unwrap()
        );
        assert_eq!(
            InstallLocation::PreferExternal,
            InstallLocation::from_str("preferExternal").unwrap()
        );
        assert!(InstallLocation::from_str("Razican").is_err());
    }

    #[test]
    fn it_permission_checklist() {
        let mut checklist = PermissionChecklist::default();
        checklist.set_needs_permission(Permission::AndroidPermissionInternet);

        assert!(checklist.needs_permission(Permission::AndroidPermissionInternet,));
        assert!(!checklist.needs_permission(Permission::AndroidPermissionWriteExternalStorage,));
    }

    #[test]
    fn it_permission() {
        let internet = Permission::from_str("android.permission.INTERNET").unwrap();
        let storage = Permission::from_str("android.permission.WRITE_EXTERNAL_STORAGE").unwrap();

        assert_eq!(internet, Permission::AndroidPermissionInternet);
        assert_eq!(storage, Permission::AndroidPermissionWriteExternalStorage);
        assert_eq!(internet.as_str(), "android.permission.INTERNET");
        assert_eq!(
            storage.as_str(),
            "android.permission.WRITE_EXTERNAL_STORAGE"
        );
        assert!(Permission::from_str("Razican").is_err());
    }
}

#[derive(Debug)]
pub struct PermissionChecklist {
    android_permission_access_all_external_storage: bool,
    android_permission_access_checkin_properties: bool,
    android_permission_access_coarse_location: bool,
    android_permission_access_fine_location: bool,
    android_permission_access_location_extra_commands: bool,
    android_permission_access_mock_location: bool,
    android_permission_access_mtp: bool,
    android_permission_access_network_state: bool,
    android_permission_access_notification_policy: bool,
    android_permission_access_wimax_state: bool,
    android_permission_access_wifi_state: bool,
    android_permission_account_manager: bool,
    android_permission_asec_access: bool,
    android_permission_asec_create: bool,
    android_permission_asec_destroy: bool,
    android_permission_asec_mount_unmount: bool,
    android_permission_asec_rename: bool,
    android_permission_authenticate_accounts: bool,
    android_permission_battery_stats: bool,
    android_permission_bind_accessibility_service: bool,
    android_permission_bind_appwidget: bool,
    android_permission_bind_call_service: bool,
    android_permission_bind_carrier_messaging_service: bool,
    android_permission_bind_carrier_services: bool,
    android_permission_bind_chooser_target_service: bool,
    android_permission_bind_device_admin: bool,
    android_permission_bind_directory_search: bool,
    android_permission_bind_dream_service: bool,
    android_permission_bind_incall_service: bool,
    android_permission_bind_input_method: bool,
    android_permission_bind_keyguard_appwidget: bool,
    android_permission_bind_midi_device_service: bool,
    android_permission_bind_nfc_service: bool,
    android_permission_bind_notification_listener_service: bool,
    android_permission_bind_print_service: bool,
    android_permission_bind_remoteviews: bool,
    android_permission_bind_telecom_connection_service: bool,
    android_permission_bind_text_service: bool,
    android_permission_bind_tv_input: bool,
    android_permission_bind_voice_interaction: bool,
    android_permission_bind_vpn_service: bool,
    android_permission_bind_wallpaper: bool,
    android_permission_bluetooth: bool,
    android_permission_bluetooth_admin: bool,
    android_permission_bluetooth_privileged: bool,
    android_permission_bluetooth_stack: bool,
    android_permission_body_sensors: bool,
    android_permission_broadcast_package_removed: bool,
    android_permission_broadcast_sms: bool,
    android_permission_broadcast_sticky: bool,
    android_permission_broadcast_wap_push: bool,
    android_permission_call_phone: bool,
    android_permission_call_privileged: bool,
    android_permission_camera: bool,
    android_permission_camera_disable_transmit_led: bool,
    android_permission_capture_audio_output: bool,
    android_permission_capture_secure_video_output: bool,
    android_permission_capture_video_output: bool,
    android_permission_change_background_data_setting: bool,
    android_permission_change_component_enabled_state: bool,
    android_permission_change_configuration: bool,
    android_permission_change_network_state: bool,
    android_permission_change_wimax_state: bool,
    android_permission_change_wifi_multicast_state: bool,
    android_permission_change_wifi_state: bool,
    android_permission_clear_app_cache: bool,
    android_permission_connectivity_internal: bool,
    android_permission_control_location_updates: bool,
    android_permission_delete_cache_files: bool,
    android_permission_delete_packages: bool,
    android_permission_diagnostic: bool,
    android_permission_disable_keyguard: bool,
    android_permission_download_without_notification: bool,
    android_permission_dump: bool,
    android_permission_expand_status_bar: bool,
    android_permission_factory_test: bool,
    android_permission_flashlight: bool,
    android_permission_force_stop_packages: bool,
    android_permission_get_accounts: bool,
    android_permission_get_accounts_privileged: bool,
    android_permission_get_app_ops_stats: bool,
    android_permission_get_detailed_tasks: bool,
    android_permission_get_package_size: bool,
    android_permission_get_tasks: bool,
    android_permission_global_search: bool,
    android_permission_global_search_control: bool,
    android_permission_hardware_test: bool,
    android_permission_install_location_provider: bool,
    android_permission_install_packages: bool,
    android_permission_interact_across_users: bool,
    android_permission_interact_across_users_full: bool,
    android_permission_internet: bool,
    android_permission_kill_background_processes: bool,
    android_permission_location_hardware: bool,
    android_permission_loop_radio: bool,
    android_permission_manage_accounts: bool,
    android_permission_manage_activity_stacks: bool,
    android_permission_manage_documents: bool,
    android_permission_manage_usb: bool,
    android_permission_manage_users: bool,
    android_permission_master_clear: bool,
    android_permission_media_content_control: bool,
    android_permission_modify_appwidget_bind_permissions: bool,
    android_permission_modify_audio_settings: bool,
    android_permission_modify_phone_state: bool,
    android_permission_mount_format_filesystems: bool,
    android_permission_mount_unmount_filesystems: bool,
    android_permission_net_admin: bool,
    android_permission_net_tunneling: bool,
    android_permission_nfc: bool,
    android_permission_package_usage_stats: bool,
    android_permission_persistent_activity: bool,
    android_permission_process_outgoing_calls: bool,
    android_permission_read_calendar: bool,
    android_permission_read_call_log: bool,
    android_permission_read_cell_broadcasts: bool,
    android_permission_read_contacts: bool,
    android_permission_read_dream_state: bool,
    android_permission_read_external_storage: bool,
    android_permission_read_frame_buffer: bool,
    android_permission_read_input_state: bool,
    android_permission_read_logs: bool,
    android_permission_read_phone_state: bool,
    android_permission_read_privileged_phone_state: bool,
    android_permission_read_profile: bool,
    android_permission_read_sms: bool,
    android_permission_read_social_stream: bool,
    android_permission_read_sync_settings: bool,
    android_permission_read_sync_stats: bool,
    android_permission_read_user_dictionary: bool,
    android_permission_reboot: bool,
    android_permission_receive_boot_completed: bool,
    android_permission_receive_data_activity_change: bool,
    android_permission_receive_emergency_broadcast: bool,
    android_permission_receive_mms: bool,
    android_permission_receive_sms: bool,
    android_permission_receive_wap_push: bool,
    android_permission_record_audio: bool,
    android_permission_remote_audio_playback: bool,
    android_permission_remove_tasks: bool,
    android_permission_reorder_tasks: bool,
    android_permission_request_ignore_battery_optimizations: bool,
    android_permission_request_install_packages: bool,
    android_permission_restart_packages: bool,
    android_permission_retrieve_window_content: bool,
    android_permission_send_respond_via_message: bool,
    android_permission_send_sms: bool,
    android_permission_set_always_finish: bool,
    android_permission_set_animation_scale: bool,
    android_permission_set_debug_app: bool,
    android_permission_set_preferred_applications: bool,
    android_permission_set_process_limit: bool,
    android_permission_set_screen_compatibility: bool,
    android_permission_set_time: bool,
    android_permission_set_time_zone: bool,
    android_permission_set_wallpaper: bool,
    android_permission_set_wallpaper_component: bool,
    android_permission_set_wallpaper_hints: bool,
    android_permission_signal_persistent_processes: bool,
    android_permission_start_any_activity: bool,
    android_permission_status_bar: bool,
    android_permission_subscribed_feeds_read: bool,
    android_permission_system_alert_window: bool,
    android_permission_subscribed_feeds_write: bool,
    android_permission_transmit_ir: bool,
    android_permission_update_device_stats: bool,
    android_permission_use_credentials: bool,
    android_permission_use_fingerprint: bool,
    android_permission_use_sip: bool,
    android_permission_vibrate: bool,
    android_permission_wake_lock: bool,
    android_permission_write_apn_settings: bool,
    android_permission_write_calendar: bool,
    android_permission_write_call_log: bool,
    android_permission_write_contacts: bool,
    android_permission_write_dream_state: bool,
    android_permission_write_external_storage: bool,
    android_permission_write_gservices: bool,
    android_permission_write_media_storage: bool,
    android_permission_write_profile: bool,
    android_permission_write_secure_settings: bool,
    android_permission_write_settings: bool,
    android_permission_write_sms: bool,
    android_permission_write_social_stream: bool,
    android_permission_write_sync_settings: bool,
    android_permission_write_user_dictionary: bool,
    com_android_alarm_permission_set_alarm: bool,
    com_android_browser_permission_read_history_bookmarks: bool,
    com_android_browser_permission_write_history_bookmarks: bool,
    com_android_email_permission_read_attachment: bool,
    com_android_launcher_permission_install_shortcut: bool,
    com_android_launcher_permission_preload_workspace: bool,
    com_android_launcher_permission_read_settings: bool,
    com_android_launcher_permission_uninstall_shortcut: bool,
    com_android_launcher_permission_write_settings: bool,
    com_android_vending_check_license: bool,
    com_android_voicemail_permission_add_voicemail: bool,
    com_android_voicemail_permission_read_voicemail: bool,
    com_android_voicemail_permission_read_write_all_voicemail: bool,
    com_android_voicemail_permission_write_voicemail: bool,
    com_google_android_c2dm_permission_receive: bool,
    com_google_android_c2dm_permission_send: bool,
    com_google_android_gms_permission_activity_recognition: bool,
    com_google_android_googleapps_permission_google_auth: bool,
    com_google_android_googleapps_permission_google_auth_all_services: bool,
    com_google_android_googleapps_permission_google_auth_other_services: bool,
    com_google_android_googleapps_permission_google_auth_youtubeuser: bool,
    com_google_android_googleapps_permission_google_auth_adsense: bool,
    com_google_android_googleapps_permission_google_auth_adwords: bool,
    com_google_android_googleapps_permission_google_auth_ah: bool,
    com_google_android_googleapps_permission_google_auth_android: bool,
    com_google_android_googleapps_permission_google_auth_androidsecure: bool,
    com_google_android_googleapps_permission_google_auth_blogger: bool,
    com_google_android_googleapps_permission_google_auth_cl: bool,
    com_google_android_googleapps_permission_google_auth_cp: bool,
    com_google_android_googleapps_permission_google_auth_dodgeball: bool,
    com_google_android_googleapps_permission_google_auth_doraemon: bool,
    com_google_android_googleapps_permission_google_auth_finance: bool,
    com_google_android_googleapps_permission_google_auth_gbase: bool,
    com_google_android_googleapps_permission_google_auth_geowiki: bool,
    com_google_android_googleapps_permission_google_auth_goanna_mobile: bool,
    com_google_android_googleapps_permission_google_auth_grandcentral: bool,
    com_google_android_googleapps_permission_google_auth_groups2: bool,
    com_google_android_googleapps_permission_google_auth_health: bool,
    com_google_android_googleapps_permission_google_auth_ig: bool,
    com_google_android_googleapps_permission_google_auth_jotspot: bool,
    com_google_android_googleapps_permission_google_auth_knol: bool,
    com_google_android_googleapps_permission_google_auth_lh2: bool,
    com_google_android_googleapps_permission_google_auth_local: bool,
    com_google_android_googleapps_permission_google_auth_mail: bool,
    com_google_android_googleapps_permission_google_auth_mobile: bool,
    com_google_android_googleapps_permission_google_auth_news: bool,
    com_google_android_googleapps_permission_google_auth_notebook: bool,
    com_google_android_googleapps_permission_google_auth_orkut: bool,
    com_google_android_googleapps_permission_google_auth_panoramio: bool,
    com_google_android_googleapps_permission_google_auth_print: bool,
    com_google_android_googleapps_permission_google_auth_reader: bool,
    com_google_android_googleapps_permission_google_auth_sierra: bool,
    com_google_android_googleapps_permission_google_auth_sierraqa: bool,
    com_google_android_googleapps_permission_google_auth_sierrasandbox: bool,
    com_google_android_googleapps_permission_google_auth_sitemaps: bool,
    com_google_android_googleapps_permission_google_auth_speech: bool,
    com_google_android_googleapps_permission_google_auth_speechpersonalization: bool,
    com_google_android_googleapps_permission_google_auth_talk: bool,
    com_google_android_googleapps_permission_google_auth_wifi: bool,
    com_google_android_googleapps_permission_google_auth_wise: bool,
    com_google_android_googleapps_permission_google_auth_writely: bool,
    com_google_android_googleapps_permission_google_auth_youtube: bool,
    com_google_android_gtalkservice_permission_gtalk_service: bool,
    com_google_android_gtalkservice_permission_send_heartbeat: bool,
    com_google_android_permission_broadcast_data_message: bool,
    com_google_android_providers_gsf_permission_read_gservices: bool,
    com_google_android_providers_talk_permission_read_only: bool,
    com_google_android_providers_talk_permission_write_only: bool,
    com_google_android_xmpp_permission_broadcast: bool,
    com_google_android_xmpp_permission_send_receive: bool,
    com_google_android_xmpp_permission_use_xmpp_endpoint: bool,
    com_google_android_xmpp_permission_xmpp_endpoint_broadcast: bool,
}

impl PermissionChecklist {
    #[allow(clippy::too_many_lines)]
    pub fn needs_permission(&self, p: Permission) -> bool {
        match p {
            Permission::AndroidPermissionAccessAllExternalStorage => {
                self.android_permission_access_all_external_storage
            }
            Permission::AndroidPermissionAccessCheckinProperties => {
                self.android_permission_access_checkin_properties
            }
            Permission::AndroidPermissionAccessCoarseLocation => {
                self.android_permission_access_coarse_location
            }
            Permission::AndroidPermissionAccessFineLocation => {
                self.android_permission_access_fine_location
            }
            Permission::AndroidPermissionAccessLocationExtraCommands => {
                self.android_permission_access_location_extra_commands
            }
            Permission::AndroidPermissionAccessMockLocation => {
                self.android_permission_access_mock_location
            }
            Permission::AndroidPermissionAccessMtp => self.android_permission_access_mtp,
            Permission::AndroidPermissionAccessNetworkState => {
                self.android_permission_access_network_state
            }
            Permission::AndroidPermissionAccessNotificationPolicy => {
                self.android_permission_access_notification_policy
            }
            Permission::AndroidPermissionAccessWimaxState => {
                self.android_permission_access_wimax_state
            }
            Permission::AndroidPermissionAccessWifiState => {
                self.android_permission_access_wifi_state
            }
            Permission::AndroidPermissionAccountManager => self.android_permission_account_manager,
            Permission::AndroidPermissionAsecAccess => self.android_permission_asec_access,
            Permission::AndroidPermissionAsecCreate => self.android_permission_asec_create,
            Permission::AndroidPermissionAsecDestroy => self.android_permission_asec_destroy,
            Permission::AndroidPermissionAsecMountUnmount => {
                self.android_permission_asec_mount_unmount
            }
            Permission::AndroidPermissionAsecRename => self.android_permission_asec_rename,
            Permission::AndroidPermissionAuthenticateAccounts => {
                self.android_permission_authenticate_accounts
            }
            Permission::AndroidPermissionBatteryStats => self.android_permission_battery_stats,
            Permission::AndroidPermissionBindAccessibilityService => {
                self.android_permission_bind_accessibility_service
            }
            Permission::AndroidPermissionBindAppwidget => self.android_permission_bind_appwidget,
            Permission::AndroidPermissionBindCallService => {
                self.android_permission_bind_call_service
            }
            Permission::AndroidPermissionBindCarrierMessagingService => {
                self.android_permission_bind_carrier_messaging_service
            }
            Permission::AndroidPermissionBindCarrierServices => {
                self.android_permission_bind_carrier_services
            }
            Permission::AndroidPermissionBindChooserTargetService => {
                self.android_permission_bind_chooser_target_service
            }
            Permission::AndroidPermissionBindDeviceAdmin => {
                self.android_permission_bind_device_admin
            }
            Permission::AndroidPermissionBindDirectorySearch => {
                self.android_permission_bind_directory_search
            }
            Permission::AndroidPermissionBindDreamService => {
                self.android_permission_bind_dream_service
            }
            Permission::AndroidPermissionBindIncallService => {
                self.android_permission_bind_incall_service
            }
            Permission::AndroidPermissionBindInputMethod => {
                self.android_permission_bind_input_method
            }
            Permission::AndroidPermissionBindKeyguardAppwidget => {
                self.android_permission_bind_keyguard_appwidget
            }
            Permission::AndroidPermissionBindMidiDeviceService => {
                self.android_permission_bind_midi_device_service
            }
            Permission::AndroidPermissionBindNfcService => self.android_permission_bind_nfc_service,
            Permission::AndroidPermissionBindNotificationListenerService => {
                self.android_permission_bind_notification_listener_service
            }
            Permission::AndroidPermissionBindPrintService => {
                self.android_permission_bind_print_service
            }
            Permission::AndroidPermissionBindRemoteviews => {
                self.android_permission_bind_remoteviews
            }
            Permission::AndroidPermissionBindTelecomConnectionService => {
                self.android_permission_bind_telecom_connection_service
            }
            Permission::AndroidPermissionBindTextService => {
                self.android_permission_bind_text_service
            }
            Permission::AndroidPermissionBindTvInput => self.android_permission_bind_tv_input,
            Permission::AndroidPermissionBindVoiceInteraction => {
                self.android_permission_bind_voice_interaction
            }
            Permission::AndroidPermissionBindVpnService => self.android_permission_bind_vpn_service,
            Permission::AndroidPermissionBindWallpaper => self.android_permission_bind_wallpaper,
            Permission::AndroidPermissionBluetooth => self.android_permission_bluetooth,
            Permission::AndroidPermissionBluetoothAdmin => self.android_permission_bluetooth_admin,
            Permission::AndroidPermissionBluetoothPrivileged => {
                self.android_permission_bluetooth_privileged
            }
            Permission::AndroidPermissionBluetoothStack => self.android_permission_bluetooth_stack,
            Permission::AndroidPermissionBodySensors => self.android_permission_body_sensors,
            Permission::AndroidPermissionBroadcastPackageRemoved => {
                self.android_permission_broadcast_package_removed
            }
            Permission::AndroidPermissionBroadcastSms => self.android_permission_broadcast_sms,
            Permission::AndroidPermissionBroadcastSticky => {
                self.android_permission_broadcast_sticky
            }
            Permission::AndroidPermissionBroadcastWapPush => {
                self.android_permission_broadcast_wap_push
            }
            Permission::AndroidPermissionCallPhone => self.android_permission_call_phone,
            Permission::AndroidPermissionCallPrivileged => self.android_permission_call_privileged,
            Permission::AndroidPermissionCamera => self.android_permission_camera,
            Permission::AndroidPermissionCameraDisableTransmitLed => {
                self.android_permission_camera_disable_transmit_led
            }
            Permission::AndroidPermissionCaptureAudioOutput => {
                self.android_permission_capture_audio_output
            }
            Permission::AndroidPermissionCaptureSecureVideoOutput => {
                self.android_permission_capture_secure_video_output
            }
            Permission::AndroidPermissionCaptureVideoOutput => {
                self.android_permission_capture_video_output
            }
            Permission::AndroidPermissionChangeBackgroundDataSetting => {
                self.android_permission_change_background_data_setting
            }
            Permission::AndroidPermissionChangeComponentEnabledState => {
                self.android_permission_change_component_enabled_state
            }
            Permission::AndroidPermissionChangeConfiguration => {
                self.android_permission_change_configuration
            }
            Permission::AndroidPermissionChangeNetworkState => {
                self.android_permission_change_network_state
            }
            Permission::AndroidPermissionChangeWimaxState => {
                self.android_permission_change_wimax_state
            }
            Permission::AndroidPermissionChangeWifiMulticastState => {
                self.android_permission_change_wifi_multicast_state
            }
            Permission::AndroidPermissionChangeWifiState => {
                self.android_permission_change_wifi_state
            }
            Permission::AndroidPermissionClearAppCache => self.android_permission_clear_app_cache,
            Permission::AndroidPermissionConnectivityInternal => {
                self.android_permission_connectivity_internal
            }
            Permission::AndroidPermissionControlLocationUpdates => {
                self.android_permission_control_location_updates
            }
            Permission::AndroidPermissionDeleteCacheFiles => {
                self.android_permission_delete_cache_files
            }
            Permission::AndroidPermissionDeletePackages => self.android_permission_delete_packages,
            Permission::AndroidPermissionDiagnostic => self.android_permission_diagnostic,
            Permission::AndroidPermissionDisableKeyguard => {
                self.android_permission_disable_keyguard
            }
            Permission::AndroidPermissionDownloadWithoutNotification => {
                self.android_permission_download_without_notification
            }
            Permission::AndroidPermissionDump => self.android_permission_dump,
            Permission::AndroidPermissionExpandStatusBar => {
                self.android_permission_expand_status_bar
            }
            Permission::AndroidPermissionFactoryTest => self.android_permission_factory_test,
            Permission::AndroidPermissionFlashlight => self.android_permission_flashlight,
            Permission::AndroidPermissionForceStopPackages => {
                self.android_permission_force_stop_packages
            }
            Permission::AndroidPermissionGetAccounts => self.android_permission_get_accounts,
            Permission::AndroidPermissionGetAccountsPrivileged => {
                self.android_permission_get_accounts_privileged
            }
            Permission::AndroidPermissionGetAppOpsStats => {
                self.android_permission_get_app_ops_stats
            }
            Permission::AndroidPermissionGetDetailedTasks => {
                self.android_permission_get_detailed_tasks
            }
            Permission::AndroidPermissionGetPackageSize => self.android_permission_get_package_size,
            Permission::AndroidPermissionGetTasks => self.android_permission_get_tasks,
            Permission::AndroidPermissionGlobalSearch => self.android_permission_global_search,
            Permission::AndroidPermissionGlobalSearchControl => {
                self.android_permission_global_search_control
            }
            Permission::AndroidPermissionHardwareTest => self.android_permission_hardware_test,
            Permission::AndroidPermissionInstallLocationProvider => {
                self.android_permission_install_location_provider
            }
            Permission::AndroidPermissionInstallPackages => {
                self.android_permission_install_packages
            }
            Permission::AndroidPermissionInteractAcrossUsers => {
                self.android_permission_interact_across_users
            }
            Permission::AndroidPermissionInteractAcrossUsersFull => {
                self.android_permission_interact_across_users_full
            }
            Permission::AndroidPermissionInternet => self.android_permission_internet,
            Permission::AndroidPermissionKillBackgroundProcesses => {
                self.android_permission_kill_background_processes
            }
            Permission::AndroidPermissionLocationHardware => {
                self.android_permission_location_hardware
            }
            Permission::AndroidPermissionLoopRadio => self.android_permission_loop_radio,
            Permission::AndroidPermissionManageAccounts => self.android_permission_manage_accounts,
            Permission::AndroidPermissionManageActivityStacks => {
                self.android_permission_manage_activity_stacks
            }
            Permission::AndroidPermissionManageDocuments => {
                self.android_permission_manage_documents
            }
            Permission::AndroidPermissionManageUsb => self.android_permission_manage_usb,
            Permission::AndroidPermissionManageUsers => self.android_permission_manage_users,
            Permission::AndroidPermissionMasterClear => self.android_permission_master_clear,
            Permission::AndroidPermissionMediaContentControl => {
                self.android_permission_media_content_control
            }
            Permission::AndroidPermissionModifyAppwidgetBindPermissions => {
                self.android_permission_modify_appwidget_bind_permissions
            }
            Permission::AndroidPermissionModifyAudioSettings => {
                self.android_permission_modify_audio_settings
            }
            Permission::AndroidPermissionModifyPhoneState => {
                self.android_permission_modify_phone_state
            }
            Permission::AndroidPermissionMountFormatFilesystems => {
                self.android_permission_mount_format_filesystems
            }
            Permission::AndroidPermissionMountUnmountFilesystems => {
                self.android_permission_mount_unmount_filesystems
            }
            Permission::AndroidPermissionNetAdmin => self.android_permission_net_admin,
            Permission::AndroidPermissionNetTunneling => self.android_permission_net_tunneling,
            Permission::AndroidPermissionNfc => self.android_permission_nfc,
            Permission::AndroidPermissionPackageUsageStats => {
                self.android_permission_package_usage_stats
            }
            Permission::AndroidPermissionPersistentActivity => {
                self.android_permission_persistent_activity
            }
            Permission::AndroidPermissionProcessOutgoingCalls => {
                self.android_permission_process_outgoing_calls
            }
            Permission::AndroidPermissionReadCalendar => self.android_permission_read_calendar,
            Permission::AndroidPermissionReadCallLog => self.android_permission_read_call_log,
            Permission::AndroidPermissionReadCellBroadcasts => {
                self.android_permission_read_cell_broadcasts
            }
            Permission::AndroidPermissionReadContacts => self.android_permission_read_contacts,
            Permission::AndroidPermissionReadDreamState => self.android_permission_read_dream_state,
            Permission::AndroidPermissionReadExternalStorage => {
                self.android_permission_read_external_storage
            }
            Permission::AndroidPermissionReadFrameBuffer => {
                self.android_permission_read_frame_buffer
            }
            Permission::AndroidPermissionReadInputState => self.android_permission_read_input_state,
            Permission::AndroidPermissionReadLogs => self.android_permission_read_logs,
            Permission::AndroidPermissionReadPhoneState => self.android_permission_read_phone_state,
            Permission::AndroidPermissionReadPrivilegedPhoneState => {
                self.android_permission_read_privileged_phone_state
            }
            Permission::AndroidPermissionReadProfile => self.android_permission_read_profile,
            Permission::AndroidPermissionReadSms => self.android_permission_read_sms,
            Permission::AndroidPermissionReadSocialStream => {
                self.android_permission_read_social_stream
            }
            Permission::AndroidPermissionReadSyncSettings => {
                self.android_permission_read_sync_settings
            }
            Permission::AndroidPermissionReadSyncStats => self.android_permission_read_sync_stats,
            Permission::AndroidPermissionReadUserDictionary => {
                self.android_permission_read_user_dictionary
            }
            Permission::AndroidPermissionReboot => self.android_permission_reboot,
            Permission::AndroidPermissionReceiveBootCompleted => {
                self.android_permission_receive_boot_completed
            }
            Permission::AndroidPermissionReceiveDataActivityChange => {
                self.android_permission_receive_data_activity_change
            }
            Permission::AndroidPermissionReceiveEmergencyBroadcast => {
                self.android_permission_receive_emergency_broadcast
            }
            Permission::AndroidPermissionReceiveMms => self.android_permission_receive_mms,
            Permission::AndroidPermissionReceiveSms => self.android_permission_receive_sms,
            Permission::AndroidPermissionReceiveWapPush => self.android_permission_receive_wap_push,
            Permission::AndroidPermissionRecordAudio => self.android_permission_record_audio,
            Permission::AndroidPermissionRemoteAudioPlayback => {
                self.android_permission_remote_audio_playback
            }
            Permission::AndroidPermissionRemoveTasks => self.android_permission_remove_tasks,
            Permission::AndroidPermissionReorderTasks => self.android_permission_reorder_tasks,
            Permission::AndroidPermissionRequestIgnoreBatteryOptimizations => {
                self.android_permission_request_ignore_battery_optimizations
            }
            Permission::AndroidPermissionRequestInstallPackages => {
                self.android_permission_request_install_packages
            }
            Permission::AndroidPermissionRestartPackages => {
                self.android_permission_restart_packages
            }
            Permission::AndroidPermissionRetrieveWindowContent => {
                self.android_permission_retrieve_window_content
            }
            Permission::AndroidPermissionSendRespondViaMessage => {
                self.android_permission_send_respond_via_message
            }
            Permission::AndroidPermissionSendSms => self.android_permission_send_sms,
            Permission::AndroidPermissionSetAlwaysFinish => {
                self.android_permission_set_always_finish
            }
            Permission::AndroidPermissionSetAnimationScale => {
                self.android_permission_set_animation_scale
            }
            Permission::AndroidPermissionSetDebugApp => self.android_permission_set_debug_app,
            Permission::AndroidPermissionSetPreferredApplications => {
                self.android_permission_set_preferred_applications
            }
            Permission::AndroidPermissionSetProcessLimit => {
                self.android_permission_set_process_limit
            }
            Permission::AndroidPermissionSetScreenCompatibility => {
                self.android_permission_set_screen_compatibility
            }
            Permission::AndroidPermissionSetTime => self.android_permission_set_time,
            Permission::AndroidPermissionSetTimeZone => self.android_permission_set_time_zone,
            Permission::AndroidPermissionSetWallpaper => self.android_permission_set_wallpaper,
            Permission::AndroidPermissionSetWallpaperComponent => {
                self.android_permission_set_wallpaper_component
            }
            Permission::AndroidPermissionSetWallpaperHints => {
                self.android_permission_set_wallpaper_hints
            }
            Permission::AndroidPermissionSignalPersistentProcesses => {
                self.android_permission_signal_persistent_processes
            }
            Permission::AndroidPermissionStartAnyActivity => {
                self.android_permission_start_any_activity
            }
            Permission::AndroidPermissionStatusBar => self.android_permission_status_bar,
            Permission::AndroidPermissionSubscribedFeedsRead => {
                self.android_permission_subscribed_feeds_read
            }
            Permission::AndroidPermissionSystemAlertWindow => {
                self.android_permission_system_alert_window
            }
            Permission::AndroidPermissionSubscribedFeedsWrite => {
                self.android_permission_subscribed_feeds_write
            }
            Permission::AndroidPermissionTransmitIr => self.android_permission_transmit_ir,
            Permission::AndroidPermissionUpdateDeviceStats => {
                self.android_permission_update_device_stats
            }
            Permission::AndroidPermissionUseCredentials => self.android_permission_use_credentials,
            Permission::AndroidPermissionUseFingerprint => self.android_permission_use_fingerprint,
            Permission::AndroidPermissionUseSip => self.android_permission_use_sip,
            Permission::AndroidPermissionVibrate => self.android_permission_vibrate,
            Permission::AndroidPermissionWakeLock => self.android_permission_wake_lock,
            Permission::AndroidPermissionWriteApnSettings => {
                self.android_permission_write_apn_settings
            }
            Permission::AndroidPermissionWriteCalendar => self.android_permission_write_calendar,
            Permission::AndroidPermissionWriteCallLog => self.android_permission_write_call_log,
            Permission::AndroidPermissionWriteContacts => self.android_permission_write_contacts,
            Permission::AndroidPermissionWriteDreamState => {
                self.android_permission_write_dream_state
            }
            Permission::AndroidPermissionWriteExternalStorage => {
                self.android_permission_write_external_storage
            }
            Permission::AndroidPermissionWriteGservices => self.android_permission_write_gservices,
            Permission::AndroidPermissionWriteMediaStorage => {
                self.android_permission_write_media_storage
            }
            Permission::AndroidPermissionWriteProfile => self.android_permission_write_profile,
            Permission::AndroidPermissionWriteSecureSettings => {
                self.android_permission_write_secure_settings
            }
            Permission::AndroidPermissionWriteSettings => self.android_permission_write_settings,
            Permission::AndroidPermissionWriteSms => self.android_permission_write_sms,
            Permission::AndroidPermissionWriteSocialStream => {
                self.android_permission_write_social_stream
            }
            Permission::AndroidPermissionWriteSyncSettings => {
                self.android_permission_write_sync_settings
            }
            Permission::AndroidPermissionWriteUserDictionary => {
                self.android_permission_write_user_dictionary
            }
            Permission::ComAndroidAlarmPermissionSetAlarm => {
                self.com_android_alarm_permission_set_alarm
            }
            Permission::ComAndroidBrowserPermissionReadHistoryBookmarks => {
                self.com_android_browser_permission_read_history_bookmarks
            }
            Permission::ComAndroidBrowserPermissionWriteHistoryBookmarks => {
                self.com_android_browser_permission_write_history_bookmarks
            }
            Permission::ComAndroidEmailPermissionReadAttachment => {
                self.com_android_email_permission_read_attachment
            }
            Permission::ComAndroidLauncherPermissionInstallShortcut => {
                self.com_android_launcher_permission_install_shortcut
            }
            Permission::ComAndroidLauncherPermissionPreloadWorkspace => {
                self.com_android_launcher_permission_preload_workspace
            }
            Permission::ComAndroidLauncherPermissionReadSettings => {
                self.com_android_launcher_permission_read_settings
            }
            Permission::ComAndroidLauncherPermissionUninstallShortcut => {
                self.com_android_launcher_permission_uninstall_shortcut
            }
            Permission::ComAndroidLauncherPermissionWriteSettings => {
                self.com_android_launcher_permission_write_settings
            }
            Permission::ComAndroidVendingCheckLicense => self.com_android_vending_check_license,
            Permission::ComAndroidVoicemailPermissionAddVoicemail => {
                self.com_android_voicemail_permission_add_voicemail
            }
            Permission::ComAndroidVoicemailPermissionReadVoicemail => {
                self.com_android_voicemail_permission_read_voicemail
            }
            Permission::ComAndroidVoicemailPermissionReadWriteAllVoicemail => {
                self.com_android_voicemail_permission_read_write_all_voicemail
            }
            Permission::ComAndroidVoicemailPermissionWriteVoicemail => {
                self.com_android_voicemail_permission_write_voicemail
            }
            Permission::ComGoogleAndroidC2dmPermissionReceive => {
                self.com_google_android_c2dm_permission_receive
            }
            Permission::ComGoogleAndroidC2dmPermissionSend => {
                self.com_google_android_c2dm_permission_send
            }
            Permission::ComGoogleAndroidGmsPermissionActivityRecognition => {
                self.com_google_android_gms_permission_activity_recognition
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuth => {
                self.com_google_android_googleapps_permission_google_auth
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAllServices => {
                self.com_google_android_googleapps_permission_google_auth_all_services
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthOtherServices => {
                self.com_google_android_googleapps_permission_google_auth_other_services
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutubeuser => {
                self.com_google_android_googleapps_permission_google_auth_youtubeuser
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAdsense => {
                self.com_google_android_googleapps_permission_google_auth_adsense
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAdwords => {
                self.com_google_android_googleapps_permission_google_auth_adwords
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAh => {
                self.com_google_android_googleapps_permission_google_auth_ah
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroid => {
                self.com_google_android_googleapps_permission_google_auth_android
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroidsecure => {
                self.com_google_android_googleapps_permission_google_auth_androidsecure
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthBlogger => {
                self.com_google_android_googleapps_permission_google_auth_blogger
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthCl => {
                self.com_google_android_googleapps_permission_google_auth_cl
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthCp => {
                self.com_google_android_googleapps_permission_google_auth_cp
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthDodgeball => {
                self.com_google_android_googleapps_permission_google_auth_dodgeball
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthDoraemon => {
                self.com_google_android_googleapps_permission_google_auth_doraemon
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthFinance => {
                self.com_google_android_googleapps_permission_google_auth_finance
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthGbase => {
                self.com_google_android_googleapps_permission_google_auth_gbase
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthGeowiki => {
                self.com_google_android_googleapps_permission_google_auth_geowiki
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthGoannaMobile => {
                self.com_google_android_googleapps_permission_google_auth_goanna_mobile
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthGrandcentral => {
                self.com_google_android_googleapps_permission_google_auth_grandcentral
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthGroups2 => {
                self.com_google_android_googleapps_permission_google_auth_groups2
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthHealth => {
                self.com_google_android_googleapps_permission_google_auth_health
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthIg => {
                self.com_google_android_googleapps_permission_google_auth_ig
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthJotspot => {
                self.com_google_android_googleapps_permission_google_auth_jotspot
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthKnol => {
                self.com_google_android_googleapps_permission_google_auth_knol
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthLh2 => {
                self.com_google_android_googleapps_permission_google_auth_lh2
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthLocal => {
                self.com_google_android_googleapps_permission_google_auth_local
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthMail => {
                self.com_google_android_googleapps_permission_google_auth_mail
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthMobile => {
                self.com_google_android_googleapps_permission_google_auth_mobile
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthNews => {
                self.com_google_android_googleapps_permission_google_auth_news
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthNotebook => {
                self.com_google_android_googleapps_permission_google_auth_notebook
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthOrkut => {
                self.com_google_android_googleapps_permission_google_auth_orkut
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthPanoramio => {
                self.com_google_android_googleapps_permission_google_auth_panoramio
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthPrint => {
                self.com_google_android_googleapps_permission_google_auth_print
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthReader => {
                self.com_google_android_googleapps_permission_google_auth_reader
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierra => {
                self.com_google_android_googleapps_permission_google_auth_sierra
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierraqa => {
                self.com_google_android_googleapps_permission_google_auth_sierraqa
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierrasandbox => {
                self.com_google_android_googleapps_permission_google_auth_sierrasandbox
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSitemaps => {
                self.com_google_android_googleapps_permission_google_auth_sitemaps
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeech => {
                self.com_google_android_googleapps_permission_google_auth_speech
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeechpersonalization => {
                self.com_google_android_googleapps_permission_google_auth_speechpersonalization
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthTalk => {
                self.com_google_android_googleapps_permission_google_auth_talk
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthWifi => {
                self.com_google_android_googleapps_permission_google_auth_wifi
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthWise => {
                self.com_google_android_googleapps_permission_google_auth_wise
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthWritely => {
                self.com_google_android_googleapps_permission_google_auth_writely
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutube => {
                self.com_google_android_googleapps_permission_google_auth_youtube
            }
            Permission::ComGoogleAndroidGtalkservicePermissionGtalkService => {
                self.com_google_android_gtalkservice_permission_gtalk_service
            }
            Permission::ComGoogleAndroidGtalkservicePermissionSendHeartbeat => {
                self.com_google_android_gtalkservice_permission_send_heartbeat
            }
            Permission::ComGoogleAndroidPermissionBroadcastDataMessage => {
                self.com_google_android_permission_broadcast_data_message
            }
            Permission::ComGoogleAndroidProvidersGsfPermissionReadGservices => {
                self.com_google_android_providers_gsf_permission_read_gservices
            }
            Permission::ComGoogleAndroidProvidersTalkPermissionReadOnly => {
                self.com_google_android_providers_talk_permission_read_only
            }
            Permission::ComGoogleAndroidProvidersTalkPermissionWriteOnly => {
                self.com_google_android_providers_talk_permission_write_only
            }
            Permission::ComGoogleAndroidXmppPermissionBroadcast => {
                self.com_google_android_xmpp_permission_broadcast
            }
            Permission::ComGoogleAndroidXmppPermissionSendReceive => {
                self.com_google_android_xmpp_permission_send_receive
            }
            Permission::ComGoogleAndroidXmppPermissionUseXmppEndpoint => {
                self.com_google_android_xmpp_permission_use_xmpp_endpoint
            }
            Permission::ComGoogleAndroidXmppPermissionXmppEndpointBroadcast => {
                self.com_google_android_xmpp_permission_xmpp_endpoint_broadcast
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn set_needs_permission(&mut self, p: Permission) {
        match p {
            Permission::AndroidPermissionAccessAllExternalStorage => {
                self.android_permission_access_all_external_storage = true
            }
            Permission::AndroidPermissionAccessCheckinProperties => {
                self.android_permission_access_checkin_properties = true
            }
            Permission::AndroidPermissionAccessCoarseLocation => {
                self.android_permission_access_coarse_location = true
            }
            Permission::AndroidPermissionAccessFineLocation => {
                self.android_permission_access_fine_location = true
            }
            Permission::AndroidPermissionAccessLocationExtraCommands => {
                self.android_permission_access_location_extra_commands = true
            }
            Permission::AndroidPermissionAccessMockLocation => {
                self.android_permission_access_mock_location = true
            }
            Permission::AndroidPermissionAccessMtp => self.android_permission_access_mtp = true,
            Permission::AndroidPermissionAccessNetworkState => {
                self.android_permission_access_network_state = true
            }
            Permission::AndroidPermissionAccessNotificationPolicy => {
                self.android_permission_access_notification_policy = true
            }
            Permission::AndroidPermissionAccessWimaxState => {
                self.android_permission_access_wimax_state = true
            }
            Permission::AndroidPermissionAccessWifiState => {
                self.android_permission_access_wifi_state = true
            }
            Permission::AndroidPermissionAccountManager => {
                self.android_permission_account_manager = true
            }
            Permission::AndroidPermissionAsecAccess => self.android_permission_asec_access = true,
            Permission::AndroidPermissionAsecCreate => self.android_permission_asec_create = true,
            Permission::AndroidPermissionAsecDestroy => self.android_permission_asec_destroy = true,
            Permission::AndroidPermissionAsecMountUnmount => {
                self.android_permission_asec_mount_unmount = true
            }
            Permission::AndroidPermissionAsecRename => self.android_permission_asec_rename = true,
            Permission::AndroidPermissionAuthenticateAccounts => {
                self.android_permission_authenticate_accounts = true
            }
            Permission::AndroidPermissionBatteryStats => {
                self.android_permission_battery_stats = true
            }
            Permission::AndroidPermissionBindAccessibilityService => {
                self.android_permission_bind_accessibility_service = true
            }
            Permission::AndroidPermissionBindAppwidget => {
                self.android_permission_bind_appwidget = true
            }
            Permission::AndroidPermissionBindCallService => {
                self.android_permission_bind_call_service = true
            }
            Permission::AndroidPermissionBindCarrierMessagingService => {
                self.android_permission_bind_carrier_messaging_service = true
            }
            Permission::AndroidPermissionBindCarrierServices => {
                self.android_permission_bind_carrier_services = true
            }
            Permission::AndroidPermissionBindChooserTargetService => {
                self.android_permission_bind_chooser_target_service = true
            }
            Permission::AndroidPermissionBindDeviceAdmin => {
                self.android_permission_bind_device_admin = true
            }
            Permission::AndroidPermissionBindDirectorySearch => {
                self.android_permission_bind_directory_search = true
            }
            Permission::AndroidPermissionBindDreamService => {
                self.android_permission_bind_dream_service = true
            }
            Permission::AndroidPermissionBindIncallService => {
                self.android_permission_bind_incall_service = true
            }
            Permission::AndroidPermissionBindInputMethod => {
                self.android_permission_bind_input_method = true
            }
            Permission::AndroidPermissionBindKeyguardAppwidget => {
                self.android_permission_bind_keyguard_appwidget = true
            }
            Permission::AndroidPermissionBindMidiDeviceService => {
                self.android_permission_bind_midi_device_service = true
            }
            Permission::AndroidPermissionBindNfcService => {
                self.android_permission_bind_nfc_service = true
            }
            Permission::AndroidPermissionBindNotificationListenerService => {
                self.android_permission_bind_notification_listener_service = true
            }
            Permission::AndroidPermissionBindPrintService => {
                self.android_permission_bind_print_service = true
            }
            Permission::AndroidPermissionBindRemoteviews => {
                self.android_permission_bind_remoteviews = true
            }
            Permission::AndroidPermissionBindTelecomConnectionService => {
                self.android_permission_bind_telecom_connection_service = true
            }
            Permission::AndroidPermissionBindTextService => {
                self.android_permission_bind_text_service = true
            }
            Permission::AndroidPermissionBindTvInput => {
                self.android_permission_bind_tv_input = true
            }
            Permission::AndroidPermissionBindVoiceInteraction => {
                self.android_permission_bind_voice_interaction = true
            }
            Permission::AndroidPermissionBindVpnService => {
                self.android_permission_bind_vpn_service = true
            }
            Permission::AndroidPermissionBindWallpaper => {
                self.android_permission_bind_wallpaper = true
            }
            Permission::AndroidPermissionBluetooth => self.android_permission_bluetooth = true,
            Permission::AndroidPermissionBluetoothAdmin => {
                self.android_permission_bluetooth_admin = true
            }
            Permission::AndroidPermissionBluetoothPrivileged => {
                self.android_permission_bluetooth_privileged = true
            }
            Permission::AndroidPermissionBluetoothStack => {
                self.android_permission_bluetooth_stack = true
            }
            Permission::AndroidPermissionBodySensors => self.android_permission_body_sensors = true,
            Permission::AndroidPermissionBroadcastPackageRemoved => {
                self.android_permission_broadcast_package_removed = true
            }
            Permission::AndroidPermissionBroadcastSms => {
                self.android_permission_broadcast_sms = true
            }
            Permission::AndroidPermissionBroadcastSticky => {
                self.android_permission_broadcast_sticky = true
            }
            Permission::AndroidPermissionBroadcastWapPush => {
                self.android_permission_broadcast_wap_push = true
            }
            Permission::AndroidPermissionCallPhone => self.android_permission_call_phone = true,
            Permission::AndroidPermissionCallPrivileged => {
                self.android_permission_call_privileged = true
            }
            Permission::AndroidPermissionCamera => self.android_permission_camera = true,
            Permission::AndroidPermissionCameraDisableTransmitLed => {
                self.android_permission_camera_disable_transmit_led = true
            }
            Permission::AndroidPermissionCaptureAudioOutput => {
                self.android_permission_capture_audio_output = true
            }
            Permission::AndroidPermissionCaptureSecureVideoOutput => {
                self.android_permission_capture_secure_video_output = true
            }
            Permission::AndroidPermissionCaptureVideoOutput => {
                self.android_permission_capture_video_output = true
            }
            Permission::AndroidPermissionChangeBackgroundDataSetting => {
                self.android_permission_change_background_data_setting = true
            }
            Permission::AndroidPermissionChangeComponentEnabledState => {
                self.android_permission_change_component_enabled_state = true
            }
            Permission::AndroidPermissionChangeConfiguration => {
                self.android_permission_change_configuration = true
            }
            Permission::AndroidPermissionChangeNetworkState => {
                self.android_permission_change_network_state = true
            }
            Permission::AndroidPermissionChangeWimaxState => {
                self.android_permission_change_wimax_state = true
            }
            Permission::AndroidPermissionChangeWifiMulticastState => {
                self.android_permission_change_wifi_multicast_state = true
            }
            Permission::AndroidPermissionChangeWifiState => {
                self.android_permission_change_wifi_state = true
            }
            Permission::AndroidPermissionClearAppCache => {
                self.android_permission_clear_app_cache = true
            }
            Permission::AndroidPermissionConnectivityInternal => {
                self.android_permission_connectivity_internal = true
            }
            Permission::AndroidPermissionControlLocationUpdates => {
                self.android_permission_control_location_updates = true
            }
            Permission::AndroidPermissionDeleteCacheFiles => {
                self.android_permission_delete_cache_files = true
            }
            Permission::AndroidPermissionDeletePackages => {
                self.android_permission_delete_packages = true
            }
            Permission::AndroidPermissionDiagnostic => self.android_permission_diagnostic = true,
            Permission::AndroidPermissionDisableKeyguard => {
                self.android_permission_disable_keyguard = true
            }
            Permission::AndroidPermissionDownloadWithoutNotification => {
                self.android_permission_download_without_notification = true
            }
            Permission::AndroidPermissionDump => self.android_permission_dump = true,
            Permission::AndroidPermissionExpandStatusBar => {
                self.android_permission_expand_status_bar = true
            }
            Permission::AndroidPermissionFactoryTest => self.android_permission_factory_test = true,
            Permission::AndroidPermissionFlashlight => self.android_permission_flashlight = true,
            Permission::AndroidPermissionForceStopPackages => {
                self.android_permission_force_stop_packages = true
            }
            Permission::AndroidPermissionGetAccounts => self.android_permission_get_accounts = true,
            Permission::AndroidPermissionGetAccountsPrivileged => {
                self.android_permission_get_accounts_privileged = true
            }
            Permission::AndroidPermissionGetAppOpsStats => {
                self.android_permission_get_app_ops_stats = true
            }
            Permission::AndroidPermissionGetDetailedTasks => {
                self.android_permission_get_detailed_tasks = true
            }
            Permission::AndroidPermissionGetPackageSize => {
                self.android_permission_get_package_size = true
            }
            Permission::AndroidPermissionGetTasks => self.android_permission_get_tasks = true,
            Permission::AndroidPermissionGlobalSearch => {
                self.android_permission_global_search = true
            }
            Permission::AndroidPermissionGlobalSearchControl => {
                self.android_permission_global_search_control = true
            }
            Permission::AndroidPermissionHardwareTest => {
                self.android_permission_hardware_test = true
            }
            Permission::AndroidPermissionInstallLocationProvider => {
                self.android_permission_install_location_provider = true
            }
            Permission::AndroidPermissionInstallPackages => {
                self.android_permission_install_packages = true
            }
            Permission::AndroidPermissionInteractAcrossUsers => {
                self.android_permission_interact_across_users = true
            }
            Permission::AndroidPermissionInteractAcrossUsersFull => {
                self.android_permission_interact_across_users_full = true
            }
            Permission::AndroidPermissionInternet => self.android_permission_internet = true,
            Permission::AndroidPermissionKillBackgroundProcesses => {
                self.android_permission_kill_background_processes = true
            }
            Permission::AndroidPermissionLocationHardware => {
                self.android_permission_location_hardware = true
            }
            Permission::AndroidPermissionLoopRadio => self.android_permission_loop_radio = true,
            Permission::AndroidPermissionManageAccounts => {
                self.android_permission_manage_accounts = true
            }
            Permission::AndroidPermissionManageActivityStacks => {
                self.android_permission_manage_activity_stacks = true
            }
            Permission::AndroidPermissionManageDocuments => {
                self.android_permission_manage_documents = true
            }
            Permission::AndroidPermissionManageUsb => self.android_permission_manage_usb = true,
            Permission::AndroidPermissionManageUsers => self.android_permission_manage_users = true,
            Permission::AndroidPermissionMasterClear => self.android_permission_master_clear = true,
            Permission::AndroidPermissionMediaContentControl => {
                self.android_permission_media_content_control = true
            }
            Permission::AndroidPermissionModifyAppwidgetBindPermissions => {
                self.android_permission_modify_appwidget_bind_permissions = true
            }
            Permission::AndroidPermissionModifyAudioSettings => {
                self.android_permission_modify_audio_settings = true
            }
            Permission::AndroidPermissionModifyPhoneState => {
                self.android_permission_modify_phone_state = true
            }
            Permission::AndroidPermissionMountFormatFilesystems => {
                self.android_permission_mount_format_filesystems = true
            }
            Permission::AndroidPermissionMountUnmountFilesystems => {
                self.android_permission_mount_unmount_filesystems = true
            }
            Permission::AndroidPermissionNetAdmin => self.android_permission_net_admin = true,
            Permission::AndroidPermissionNetTunneling => {
                self.android_permission_net_tunneling = true
            }
            Permission::AndroidPermissionNfc => self.android_permission_nfc = true,
            Permission::AndroidPermissionPackageUsageStats => {
                self.android_permission_package_usage_stats = true
            }
            Permission::AndroidPermissionPersistentActivity => {
                self.android_permission_persistent_activity = true
            }
            Permission::AndroidPermissionProcessOutgoingCalls => {
                self.android_permission_process_outgoing_calls = true
            }
            Permission::AndroidPermissionReadCalendar => {
                self.android_permission_read_calendar = true
            }
            Permission::AndroidPermissionReadCallLog => {
                self.android_permission_read_call_log = true
            }
            Permission::AndroidPermissionReadCellBroadcasts => {
                self.android_permission_read_cell_broadcasts = true
            }
            Permission::AndroidPermissionReadContacts => {
                self.android_permission_read_contacts = true
            }
            Permission::AndroidPermissionReadDreamState => {
                self.android_permission_read_dream_state = true
            }
            Permission::AndroidPermissionReadExternalStorage => {
                self.android_permission_read_external_storage = true
            }
            Permission::AndroidPermissionReadFrameBuffer => {
                self.android_permission_read_frame_buffer = true
            }
            Permission::AndroidPermissionReadInputState => {
                self.android_permission_read_input_state = true
            }
            Permission::AndroidPermissionReadLogs => self.android_permission_read_logs = true,
            Permission::AndroidPermissionReadPhoneState => {
                self.android_permission_read_phone_state = true
            }
            Permission::AndroidPermissionReadPrivilegedPhoneState => {
                self.android_permission_read_privileged_phone_state = true
            }
            Permission::AndroidPermissionReadProfile => self.android_permission_read_profile = true,
            Permission::AndroidPermissionReadSms => self.android_permission_read_sms = true,
            Permission::AndroidPermissionReadSocialStream => {
                self.android_permission_read_social_stream = true
            }
            Permission::AndroidPermissionReadSyncSettings => {
                self.android_permission_read_sync_settings = true
            }
            Permission::AndroidPermissionReadSyncStats => {
                self.android_permission_read_sync_stats = true
            }
            Permission::AndroidPermissionReadUserDictionary => {
                self.android_permission_read_user_dictionary = true
            }
            Permission::AndroidPermissionReboot => self.android_permission_reboot = true,
            Permission::AndroidPermissionReceiveBootCompleted => {
                self.android_permission_receive_boot_completed = true
            }
            Permission::AndroidPermissionReceiveDataActivityChange => {
                self.android_permission_receive_data_activity_change = true
            }
            Permission::AndroidPermissionReceiveEmergencyBroadcast => {
                self.android_permission_receive_emergency_broadcast = true
            }
            Permission::AndroidPermissionReceiveMms => self.android_permission_receive_mms = true,
            Permission::AndroidPermissionReceiveSms => self.android_permission_receive_sms = true,
            Permission::AndroidPermissionReceiveWapPush => {
                self.android_permission_receive_wap_push = true
            }
            Permission::AndroidPermissionRecordAudio => self.android_permission_record_audio = true,
            Permission::AndroidPermissionRemoteAudioPlayback => {
                self.android_permission_remote_audio_playback = true
            }
            Permission::AndroidPermissionRemoveTasks => self.android_permission_remove_tasks = true,
            Permission::AndroidPermissionReorderTasks => {
                self.android_permission_reorder_tasks = true
            }
            Permission::AndroidPermissionRequestIgnoreBatteryOptimizations => {
                self.android_permission_request_ignore_battery_optimizations = true
            }
            Permission::AndroidPermissionRequestInstallPackages => {
                self.android_permission_request_install_packages = true
            }
            Permission::AndroidPermissionRestartPackages => {
                self.android_permission_restart_packages = true
            }
            Permission::AndroidPermissionRetrieveWindowContent => {
                self.android_permission_retrieve_window_content = true
            }
            Permission::AndroidPermissionSendRespondViaMessage => {
                self.android_permission_send_respond_via_message = true
            }
            Permission::AndroidPermissionSendSms => self.android_permission_send_sms = true,
            Permission::AndroidPermissionSetAlwaysFinish => {
                self.android_permission_set_always_finish = true
            }
            Permission::AndroidPermissionSetAnimationScale => {
                self.android_permission_set_animation_scale = true
            }
            Permission::AndroidPermissionSetDebugApp => {
                self.android_permission_set_debug_app = true
            }
            Permission::AndroidPermissionSetPreferredApplications => {
                self.android_permission_set_preferred_applications = true
            }
            Permission::AndroidPermissionSetProcessLimit => {
                self.android_permission_set_process_limit = true
            }
            Permission::AndroidPermissionSetScreenCompatibility => {
                self.android_permission_set_screen_compatibility = true
            }
            Permission::AndroidPermissionSetTime => self.android_permission_set_time = true,
            Permission::AndroidPermissionSetTimeZone => {
                self.android_permission_set_time_zone = true
            }
            Permission::AndroidPermissionSetWallpaper => {
                self.android_permission_set_wallpaper = true
            }
            Permission::AndroidPermissionSetWallpaperComponent => {
                self.android_permission_set_wallpaper_component = true
            }
            Permission::AndroidPermissionSetWallpaperHints => {
                self.android_permission_set_wallpaper_hints = true
            }
            Permission::AndroidPermissionSignalPersistentProcesses => {
                self.android_permission_signal_persistent_processes = true
            }
            Permission::AndroidPermissionStartAnyActivity => {
                self.android_permission_start_any_activity = true
            }
            Permission::AndroidPermissionStatusBar => self.android_permission_status_bar = true,
            Permission::AndroidPermissionSubscribedFeedsRead => {
                self.android_permission_subscribed_feeds_read = true
            }
            Permission::AndroidPermissionSystemAlertWindow => {
                self.android_permission_system_alert_window = true
            }
            Permission::AndroidPermissionSubscribedFeedsWrite => {
                self.android_permission_subscribed_feeds_write = true
            }
            Permission::AndroidPermissionTransmitIr => self.android_permission_transmit_ir = true,
            Permission::AndroidPermissionUpdateDeviceStats => {
                self.android_permission_update_device_stats = true
            }
            Permission::AndroidPermissionUseCredentials => {
                self.android_permission_use_credentials = true
            }
            Permission::AndroidPermissionUseFingerprint => {
                self.android_permission_use_fingerprint = true
            }
            Permission::AndroidPermissionUseSip => self.android_permission_use_sip = true,
            Permission::AndroidPermissionVibrate => self.android_permission_vibrate = true,
            Permission::AndroidPermissionWakeLock => self.android_permission_wake_lock = true,
            Permission::AndroidPermissionWriteApnSettings => {
                self.android_permission_write_apn_settings = true
            }
            Permission::AndroidPermissionWriteCalendar => {
                self.android_permission_write_calendar = true
            }
            Permission::AndroidPermissionWriteCallLog => {
                self.android_permission_write_call_log = true
            }
            Permission::AndroidPermissionWriteContacts => {
                self.android_permission_write_contacts = true
            }
            Permission::AndroidPermissionWriteDreamState => {
                self.android_permission_write_dream_state = true
            }
            Permission::AndroidPermissionWriteExternalStorage => {
                self.android_permission_write_external_storage = true
            }
            Permission::AndroidPermissionWriteGservices => {
                self.android_permission_write_gservices = true
            }
            Permission::AndroidPermissionWriteMediaStorage => {
                self.android_permission_write_media_storage = true
            }
            Permission::AndroidPermissionWriteProfile => {
                self.android_permission_write_profile = true
            }
            Permission::AndroidPermissionWriteSecureSettings => {
                self.android_permission_write_secure_settings = true
            }
            Permission::AndroidPermissionWriteSettings => {
                self.android_permission_write_settings = true
            }
            Permission::AndroidPermissionWriteSms => self.android_permission_write_sms = true,
            Permission::AndroidPermissionWriteSocialStream => {
                self.android_permission_write_social_stream = true
            }
            Permission::AndroidPermissionWriteSyncSettings => {
                self.android_permission_write_sync_settings = true
            }
            Permission::AndroidPermissionWriteUserDictionary => {
                self.android_permission_write_user_dictionary = true
            }
            Permission::ComAndroidAlarmPermissionSetAlarm => {
                self.com_android_alarm_permission_set_alarm = true
            }
            Permission::ComAndroidBrowserPermissionReadHistoryBookmarks => {
                self.com_android_browser_permission_read_history_bookmarks = true
            }
            Permission::ComAndroidBrowserPermissionWriteHistoryBookmarks => {
                self.com_android_browser_permission_write_history_bookmarks = true
            }
            Permission::ComAndroidEmailPermissionReadAttachment => {
                self.com_android_email_permission_read_attachment = true
            }
            Permission::ComAndroidLauncherPermissionInstallShortcut => {
                self.com_android_launcher_permission_install_shortcut = true
            }
            Permission::ComAndroidLauncherPermissionPreloadWorkspace => {
                self.com_android_launcher_permission_preload_workspace = true
            }
            Permission::ComAndroidLauncherPermissionReadSettings => {
                self.com_android_launcher_permission_read_settings = true
            }
            Permission::ComAndroidLauncherPermissionUninstallShortcut => {
                self.com_android_launcher_permission_uninstall_shortcut = true
            }
            Permission::ComAndroidLauncherPermissionWriteSettings => {
                self.com_android_launcher_permission_write_settings = true
            }
            Permission::ComAndroidVendingCheckLicense => {
                self.com_android_vending_check_license = true
            }
            Permission::ComAndroidVoicemailPermissionAddVoicemail => {
                self.com_android_voicemail_permission_add_voicemail = true
            }
            Permission::ComAndroidVoicemailPermissionReadVoicemail => {
                self.com_android_voicemail_permission_read_voicemail = true
            }
            Permission::ComAndroidVoicemailPermissionReadWriteAllVoicemail => {
                self.com_android_voicemail_permission_read_write_all_voicemail = true
            }
            Permission::ComAndroidVoicemailPermissionWriteVoicemail => {
                self.com_android_voicemail_permission_write_voicemail = true
            }
            Permission::ComGoogleAndroidC2dmPermissionReceive => {
                self.com_google_android_c2dm_permission_receive = true
            }
            Permission::ComGoogleAndroidC2dmPermissionSend => {
                self.com_google_android_c2dm_permission_send = true
            }
            Permission::ComGoogleAndroidGmsPermissionActivityRecognition => {
                self.com_google_android_gms_permission_activity_recognition = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuth => {
                self.com_google_android_googleapps_permission_google_auth = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAllServices => {
                self.com_google_android_googleapps_permission_google_auth_all_services = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthOtherServices => {
                self.com_google_android_googleapps_permission_google_auth_other_services = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutubeuser => {
                self.com_google_android_googleapps_permission_google_auth_youtubeuser = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAdsense => {
                self.com_google_android_googleapps_permission_google_auth_adsense = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAdwords => {
                self.com_google_android_googleapps_permission_google_auth_adwords = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAh => {
                self.com_google_android_googleapps_permission_google_auth_ah = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroid => {
                self.com_google_android_googleapps_permission_google_auth_android = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroidsecure => {
                self.com_google_android_googleapps_permission_google_auth_androidsecure = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthBlogger => {
                self.com_google_android_googleapps_permission_google_auth_blogger = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthCl => {
                self.com_google_android_googleapps_permission_google_auth_cl = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthCp => {
                self.com_google_android_googleapps_permission_google_auth_cp = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthDodgeball => {
                self.com_google_android_googleapps_permission_google_auth_dodgeball = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthDoraemon => {
                self.com_google_android_googleapps_permission_google_auth_doraemon = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthFinance => {
                self.com_google_android_googleapps_permission_google_auth_finance = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthGbase => {
                self.com_google_android_googleapps_permission_google_auth_gbase = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthGeowiki => {
                self.com_google_android_googleapps_permission_google_auth_geowiki = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthGoannaMobile => {
                self.com_google_android_googleapps_permission_google_auth_goanna_mobile = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthGrandcentral => {
                self.com_google_android_googleapps_permission_google_auth_grandcentral = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthGroups2 => {
                self.com_google_android_googleapps_permission_google_auth_groups2 = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthHealth => {
                self.com_google_android_googleapps_permission_google_auth_health = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthIg => {
                self.com_google_android_googleapps_permission_google_auth_ig = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthJotspot => {
                self.com_google_android_googleapps_permission_google_auth_jotspot = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthKnol => {
                self.com_google_android_googleapps_permission_google_auth_knol = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthLh2 => {
                self.com_google_android_googleapps_permission_google_auth_lh2 = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthLocal => {
                self.com_google_android_googleapps_permission_google_auth_local = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthMail => {
                self.com_google_android_googleapps_permission_google_auth_mail = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthMobile => {
                self.com_google_android_googleapps_permission_google_auth_mobile = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthNews => {
                self.com_google_android_googleapps_permission_google_auth_news = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthNotebook => {
                self.com_google_android_googleapps_permission_google_auth_notebook = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthOrkut => {
                self.com_google_android_googleapps_permission_google_auth_orkut = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthPanoramio => {
                self.com_google_android_googleapps_permission_google_auth_panoramio = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthPrint => {
                self.com_google_android_googleapps_permission_google_auth_print = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthReader => {
                self.com_google_android_googleapps_permission_google_auth_reader = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierra => {
                self.com_google_android_googleapps_permission_google_auth_sierra = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierraqa => {
                self.com_google_android_googleapps_permission_google_auth_sierraqa = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierrasandbox => {
                self.com_google_android_googleapps_permission_google_auth_sierrasandbox = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSitemaps => {
                self.com_google_android_googleapps_permission_google_auth_sitemaps = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeech => {
                self.com_google_android_googleapps_permission_google_auth_speech = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeechpersonalization => {
                self.com_google_android_googleapps_permission_google_auth_speechpersonalization =
                    true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthTalk => {
                self.com_google_android_googleapps_permission_google_auth_talk = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthWifi => {
                self.com_google_android_googleapps_permission_google_auth_wifi = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthWise => {
                self.com_google_android_googleapps_permission_google_auth_wise = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthWritely => {
                self.com_google_android_googleapps_permission_google_auth_writely = true
            }
            Permission::ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutube => {
                self.com_google_android_googleapps_permission_google_auth_youtube = true
            }
            Permission::ComGoogleAndroidGtalkservicePermissionGtalkService => {
                self.com_google_android_gtalkservice_permission_gtalk_service = true
            }
            Permission::ComGoogleAndroidGtalkservicePermissionSendHeartbeat => {
                self.com_google_android_gtalkservice_permission_send_heartbeat = true
            }
            Permission::ComGoogleAndroidPermissionBroadcastDataMessage => {
                self.com_google_android_permission_broadcast_data_message = true
            }
            Permission::ComGoogleAndroidProvidersGsfPermissionReadGservices => {
                self.com_google_android_providers_gsf_permission_read_gservices = true
            }
            Permission::ComGoogleAndroidProvidersTalkPermissionReadOnly => {
                self.com_google_android_providers_talk_permission_read_only = true
            }
            Permission::ComGoogleAndroidProvidersTalkPermissionWriteOnly => {
                self.com_google_android_providers_talk_permission_write_only = true
            }
            Permission::ComGoogleAndroidXmppPermissionBroadcast => {
                self.com_google_android_xmpp_permission_broadcast = true
            }
            Permission::ComGoogleAndroidXmppPermissionSendReceive => {
                self.com_google_android_xmpp_permission_send_receive = true
            }
            Permission::ComGoogleAndroidXmppPermissionUseXmppEndpoint => {
                self.com_google_android_xmpp_permission_use_xmpp_endpoint = true
            }
            Permission::ComGoogleAndroidXmppPermissionXmppEndpointBroadcast => {
                self.com_google_android_xmpp_permission_xmpp_endpoint_broadcast = true
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
impl Default for PermissionChecklist {
    fn default() -> Self {
        Self {
            android_permission_access_all_external_storage: false,
            android_permission_access_checkin_properties: false,
            android_permission_access_coarse_location: false,
            android_permission_access_fine_location: false,
            android_permission_access_location_extra_commands: false,
            android_permission_access_mock_location: false,
            android_permission_access_mtp: false,
            android_permission_access_network_state: false,
            android_permission_access_notification_policy: false,
            android_permission_access_wimax_state: false,
            android_permission_access_wifi_state: false,
            android_permission_account_manager: false,
            android_permission_asec_access: false,
            android_permission_asec_create: false,
            android_permission_asec_destroy: false,
            android_permission_asec_mount_unmount: false,
            android_permission_asec_rename: false,
            android_permission_authenticate_accounts: false,
            android_permission_battery_stats: false,
            android_permission_bind_accessibility_service: false,
            android_permission_bind_appwidget: false,
            android_permission_bind_call_service: false,
            android_permission_bind_carrier_messaging_service: false,
            android_permission_bind_carrier_services: false,
            android_permission_bind_chooser_target_service: false,
            android_permission_bind_device_admin: false,
            android_permission_bind_directory_search: false,
            android_permission_bind_dream_service: false,
            android_permission_bind_incall_service: false,
            android_permission_bind_input_method: false,
            android_permission_bind_keyguard_appwidget: false,
            android_permission_bind_midi_device_service: false,
            android_permission_bind_nfc_service: false,
            android_permission_bind_notification_listener_service: false,
            android_permission_bind_print_service: false,
            android_permission_bind_remoteviews: false,
            android_permission_bind_telecom_connection_service: false,
            android_permission_bind_text_service: false,
            android_permission_bind_tv_input: false,
            android_permission_bind_voice_interaction: false,
            android_permission_bind_vpn_service: false,
            android_permission_bind_wallpaper: false,
            android_permission_bluetooth: false,
            android_permission_bluetooth_admin: false,
            android_permission_bluetooth_privileged: false,
            android_permission_bluetooth_stack: false,
            android_permission_body_sensors: false,
            android_permission_broadcast_package_removed: false,
            android_permission_broadcast_sms: false,
            android_permission_broadcast_sticky: false,
            android_permission_broadcast_wap_push: false,
            android_permission_call_phone: false,
            android_permission_call_privileged: false,
            android_permission_camera: false,
            android_permission_camera_disable_transmit_led: false,
            android_permission_capture_audio_output: false,
            android_permission_capture_secure_video_output: false,
            android_permission_capture_video_output: false,
            android_permission_change_background_data_setting: false,
            android_permission_change_component_enabled_state: false,
            android_permission_change_configuration: false,
            android_permission_change_network_state: false,
            android_permission_change_wimax_state: false,
            android_permission_change_wifi_multicast_state: false,
            android_permission_change_wifi_state: false,
            android_permission_clear_app_cache: false,
            android_permission_connectivity_internal: false,
            android_permission_control_location_updates: false,
            android_permission_delete_cache_files: false,
            android_permission_delete_packages: false,
            android_permission_diagnostic: false,
            android_permission_disable_keyguard: false,
            android_permission_download_without_notification: false,
            android_permission_dump: false,
            android_permission_expand_status_bar: false,
            android_permission_factory_test: false,
            android_permission_flashlight: false,
            android_permission_force_stop_packages: false,
            android_permission_get_accounts: false,
            android_permission_get_accounts_privileged: false,
            android_permission_get_app_ops_stats: false,
            android_permission_get_detailed_tasks: false,
            android_permission_get_package_size: false,
            android_permission_get_tasks: false,
            android_permission_global_search: false,
            android_permission_global_search_control: false,
            android_permission_hardware_test: false,
            android_permission_install_location_provider: false,
            android_permission_install_packages: false,
            android_permission_interact_across_users: false,
            android_permission_interact_across_users_full: false,
            android_permission_internet: false,
            android_permission_kill_background_processes: false,
            android_permission_location_hardware: false,
            android_permission_loop_radio: false,
            android_permission_manage_accounts: false,
            android_permission_manage_activity_stacks: false,
            android_permission_manage_documents: false,
            android_permission_manage_usb: false,
            android_permission_manage_users: false,
            android_permission_master_clear: false,
            android_permission_media_content_control: false,
            android_permission_modify_appwidget_bind_permissions: false,
            android_permission_modify_audio_settings: false,
            android_permission_modify_phone_state: false,
            android_permission_mount_format_filesystems: false,
            android_permission_mount_unmount_filesystems: false,
            android_permission_net_admin: false,
            android_permission_net_tunneling: false,
            android_permission_nfc: false,
            android_permission_package_usage_stats: false,
            android_permission_persistent_activity: false,
            android_permission_process_outgoing_calls: false,
            android_permission_read_calendar: false,
            android_permission_read_call_log: false,
            android_permission_read_cell_broadcasts: false,
            android_permission_read_contacts: false,
            android_permission_read_dream_state: false,
            android_permission_read_external_storage: false,
            android_permission_read_frame_buffer: false,
            android_permission_read_input_state: false,
            android_permission_read_logs: false,
            android_permission_read_phone_state: false,
            android_permission_read_privileged_phone_state: false,
            android_permission_read_profile: false,
            android_permission_read_sms: false,
            android_permission_read_social_stream: false,
            android_permission_read_sync_settings: false,
            android_permission_read_sync_stats: false,
            android_permission_read_user_dictionary: false,
            android_permission_reboot: false,
            android_permission_receive_boot_completed: false,
            android_permission_receive_data_activity_change: false,
            android_permission_receive_emergency_broadcast: false,
            android_permission_receive_mms: false,
            android_permission_receive_sms: false,
            android_permission_receive_wap_push: false,
            android_permission_record_audio: false,
            android_permission_remote_audio_playback: false,
            android_permission_remove_tasks: false,
            android_permission_reorder_tasks: false,
            android_permission_request_ignore_battery_optimizations: false,
            android_permission_request_install_packages: false,
            android_permission_restart_packages: false,
            android_permission_retrieve_window_content: false,
            android_permission_send_respond_via_message: false,
            android_permission_send_sms: false,
            android_permission_set_always_finish: false,
            android_permission_set_animation_scale: false,
            android_permission_set_debug_app: false,
            android_permission_set_preferred_applications: false,
            android_permission_set_process_limit: false,
            android_permission_set_screen_compatibility: false,
            android_permission_set_time: false,
            android_permission_set_time_zone: false,
            android_permission_set_wallpaper: false,
            android_permission_set_wallpaper_component: false,
            android_permission_set_wallpaper_hints: false,
            android_permission_signal_persistent_processes: false,
            android_permission_start_any_activity: false,
            android_permission_status_bar: false,
            android_permission_subscribed_feeds_read: false,
            android_permission_system_alert_window: false,
            android_permission_subscribed_feeds_write: false,
            android_permission_transmit_ir: false,
            android_permission_update_device_stats: false,
            android_permission_use_credentials: false,
            android_permission_use_fingerprint: false,
            android_permission_use_sip: false,
            android_permission_vibrate: false,
            android_permission_wake_lock: false,
            android_permission_write_apn_settings: false,
            android_permission_write_calendar: false,
            android_permission_write_call_log: false,
            android_permission_write_contacts: false,
            android_permission_write_dream_state: false,
            android_permission_write_external_storage: false,
            android_permission_write_gservices: false,
            android_permission_write_media_storage: false,
            android_permission_write_profile: false,
            android_permission_write_secure_settings: false,
            android_permission_write_settings: false,
            android_permission_write_sms: false,
            android_permission_write_social_stream: false,
            android_permission_write_sync_settings: false,
            android_permission_write_user_dictionary: false,
            com_android_alarm_permission_set_alarm: false,
            com_android_browser_permission_read_history_bookmarks: false,
            com_android_browser_permission_write_history_bookmarks: false,
            com_android_email_permission_read_attachment: false,
            com_android_launcher_permission_install_shortcut: false,
            com_android_launcher_permission_preload_workspace: false,
            com_android_launcher_permission_read_settings: false,
            com_android_launcher_permission_uninstall_shortcut: false,
            com_android_launcher_permission_write_settings: false,
            com_android_vending_check_license: false,
            com_android_voicemail_permission_add_voicemail: false,
            com_android_voicemail_permission_read_voicemail: false,
            com_android_voicemail_permission_read_write_all_voicemail: false,
            com_android_voicemail_permission_write_voicemail: false,
            com_google_android_c2dm_permission_receive: false,
            com_google_android_c2dm_permission_send: false,
            com_google_android_gms_permission_activity_recognition: false,
            com_google_android_googleapps_permission_google_auth: false,
            com_google_android_googleapps_permission_google_auth_all_services: false,
            com_google_android_googleapps_permission_google_auth_other_services: false,
            com_google_android_googleapps_permission_google_auth_youtubeuser: false,
            com_google_android_googleapps_permission_google_auth_adsense: false,
            com_google_android_googleapps_permission_google_auth_adwords: false,
            com_google_android_googleapps_permission_google_auth_ah: false,
            com_google_android_googleapps_permission_google_auth_android: false,
            com_google_android_googleapps_permission_google_auth_androidsecure: false,
            com_google_android_googleapps_permission_google_auth_blogger: false,
            com_google_android_googleapps_permission_google_auth_cl: false,
            com_google_android_googleapps_permission_google_auth_cp: false,
            com_google_android_googleapps_permission_google_auth_dodgeball: false,
            com_google_android_googleapps_permission_google_auth_doraemon: false,
            com_google_android_googleapps_permission_google_auth_finance: false,
            com_google_android_googleapps_permission_google_auth_gbase: false,
            com_google_android_googleapps_permission_google_auth_geowiki: false,
            com_google_android_googleapps_permission_google_auth_goanna_mobile: false,
            com_google_android_googleapps_permission_google_auth_grandcentral: false,
            com_google_android_googleapps_permission_google_auth_groups2: false,
            com_google_android_googleapps_permission_google_auth_health: false,
            com_google_android_googleapps_permission_google_auth_ig: false,
            com_google_android_googleapps_permission_google_auth_jotspot: false,
            com_google_android_googleapps_permission_google_auth_knol: false,
            com_google_android_googleapps_permission_google_auth_lh2: false,
            com_google_android_googleapps_permission_google_auth_local: false,
            com_google_android_googleapps_permission_google_auth_mail: false,
            com_google_android_googleapps_permission_google_auth_mobile: false,
            com_google_android_googleapps_permission_google_auth_news: false,
            com_google_android_googleapps_permission_google_auth_notebook: false,
            com_google_android_googleapps_permission_google_auth_orkut: false,
            com_google_android_googleapps_permission_google_auth_panoramio: false,
            com_google_android_googleapps_permission_google_auth_print: false,
            com_google_android_googleapps_permission_google_auth_reader: false,
            com_google_android_googleapps_permission_google_auth_sierra: false,
            com_google_android_googleapps_permission_google_auth_sierraqa: false,
            com_google_android_googleapps_permission_google_auth_sierrasandbox: false,
            com_google_android_googleapps_permission_google_auth_sitemaps: false,
            com_google_android_googleapps_permission_google_auth_speech: false,
            com_google_android_googleapps_permission_google_auth_speechpersonalization: false,
            com_google_android_googleapps_permission_google_auth_talk: false,
            com_google_android_googleapps_permission_google_auth_wifi: false,
            com_google_android_googleapps_permission_google_auth_wise: false,
            com_google_android_googleapps_permission_google_auth_writely: false,
            com_google_android_googleapps_permission_google_auth_youtube: false,
            com_google_android_gtalkservice_permission_gtalk_service: false,
            com_google_android_gtalkservice_permission_send_heartbeat: false,
            com_google_android_permission_broadcast_data_message: false,
            com_google_android_providers_gsf_permission_read_gservices: false,
            com_google_android_providers_talk_permission_read_only: false,
            com_google_android_providers_talk_permission_write_only: false,
            com_google_android_xmpp_permission_broadcast: false,
            com_google_android_xmpp_permission_send_receive: false,
            com_google_android_xmpp_permission_use_xmpp_endpoint: false,
            com_google_android_xmpp_permission_xmpp_endpoint_broadcast: false,
        }
    }
}

/// Enumeration describing all the known permissions.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Permission {
    AndroidPermissionAccessAllExternalStorage,
    AndroidPermissionAccessCheckinProperties,
    AndroidPermissionAccessCoarseLocation,
    AndroidPermissionAccessFineLocation,
    AndroidPermissionAccessLocationExtraCommands,
    AndroidPermissionAccessMockLocation,
    AndroidPermissionAccessMtp,
    AndroidPermissionAccessNetworkState,
    AndroidPermissionAccessNotificationPolicy,
    AndroidPermissionAccessWimaxState,
    AndroidPermissionAccessWifiState,
    AndroidPermissionAccountManager,
    AndroidPermissionAsecAccess,
    AndroidPermissionAsecCreate,
    AndroidPermissionAsecDestroy,
    AndroidPermissionAsecMountUnmount,
    AndroidPermissionAsecRename,
    AndroidPermissionAuthenticateAccounts,
    AndroidPermissionBatteryStats,
    AndroidPermissionBindAccessibilityService,
    AndroidPermissionBindAppwidget,
    AndroidPermissionBindCallService,
    AndroidPermissionBindCarrierMessagingService,
    AndroidPermissionBindCarrierServices,
    AndroidPermissionBindChooserTargetService,
    AndroidPermissionBindDeviceAdmin,
    AndroidPermissionBindDirectorySearch,
    AndroidPermissionBindDreamService,
    AndroidPermissionBindIncallService,
    AndroidPermissionBindInputMethod,
    AndroidPermissionBindKeyguardAppwidget,
    AndroidPermissionBindMidiDeviceService,
    AndroidPermissionBindNfcService,
    AndroidPermissionBindNotificationListenerService,
    AndroidPermissionBindPrintService,
    AndroidPermissionBindRemoteviews,
    AndroidPermissionBindTelecomConnectionService,
    AndroidPermissionBindTextService,
    AndroidPermissionBindTvInput,
    AndroidPermissionBindVoiceInteraction,
    AndroidPermissionBindVpnService,
    AndroidPermissionBindWallpaper,
    AndroidPermissionBluetooth,
    AndroidPermissionBluetoothAdmin,
    AndroidPermissionBluetoothPrivileged,
    AndroidPermissionBluetoothStack,
    AndroidPermissionBodySensors,
    AndroidPermissionBroadcastPackageRemoved,
    AndroidPermissionBroadcastSms,
    AndroidPermissionBroadcastSticky,
    AndroidPermissionBroadcastWapPush,
    AndroidPermissionCallPhone,
    AndroidPermissionCallPrivileged,
    AndroidPermissionCamera,
    AndroidPermissionCameraDisableTransmitLed,
    AndroidPermissionCaptureAudioOutput,
    AndroidPermissionCaptureSecureVideoOutput,
    AndroidPermissionCaptureVideoOutput,
    AndroidPermissionChangeBackgroundDataSetting,
    AndroidPermissionChangeComponentEnabledState,
    AndroidPermissionChangeConfiguration,
    AndroidPermissionChangeNetworkState,
    AndroidPermissionChangeWimaxState,
    AndroidPermissionChangeWifiMulticastState,
    AndroidPermissionChangeWifiState,
    AndroidPermissionClearAppCache,
    AndroidPermissionConnectivityInternal,
    AndroidPermissionControlLocationUpdates,
    AndroidPermissionDeleteCacheFiles,
    AndroidPermissionDeletePackages,
    AndroidPermissionDiagnostic,
    AndroidPermissionDisableKeyguard,
    AndroidPermissionDownloadWithoutNotification,
    AndroidPermissionDump,
    AndroidPermissionExpandStatusBar,
    AndroidPermissionFactoryTest,
    AndroidPermissionFlashlight,
    AndroidPermissionForceStopPackages,
    AndroidPermissionGetAccounts,
    AndroidPermissionGetAccountsPrivileged,
    AndroidPermissionGetAppOpsStats,
    AndroidPermissionGetDetailedTasks,
    AndroidPermissionGetPackageSize,
    AndroidPermissionGetTasks,
    AndroidPermissionGlobalSearch,
    AndroidPermissionGlobalSearchControl,
    AndroidPermissionHardwareTest,
    AndroidPermissionInstallLocationProvider,
    AndroidPermissionInstallPackages,
    AndroidPermissionInteractAcrossUsers,
    AndroidPermissionInteractAcrossUsersFull,
    AndroidPermissionInternet,
    AndroidPermissionKillBackgroundProcesses,
    AndroidPermissionLocationHardware,
    AndroidPermissionLoopRadio,
    AndroidPermissionManageAccounts,
    AndroidPermissionManageActivityStacks,
    AndroidPermissionManageDocuments,
    AndroidPermissionManageUsb,
    AndroidPermissionManageUsers,
    AndroidPermissionMasterClear,
    AndroidPermissionMediaContentControl,
    AndroidPermissionModifyAppwidgetBindPermissions,
    AndroidPermissionModifyAudioSettings,
    AndroidPermissionModifyPhoneState,
    AndroidPermissionMountFormatFilesystems,
    AndroidPermissionMountUnmountFilesystems,
    AndroidPermissionNetAdmin,
    AndroidPermissionNetTunneling,
    AndroidPermissionNfc,
    AndroidPermissionPackageUsageStats,
    AndroidPermissionPersistentActivity,
    AndroidPermissionProcessOutgoingCalls,
    AndroidPermissionReadCalendar,
    AndroidPermissionReadCallLog,
    AndroidPermissionReadCellBroadcasts,
    AndroidPermissionReadContacts,
    AndroidPermissionReadDreamState,
    AndroidPermissionReadExternalStorage,
    AndroidPermissionReadFrameBuffer,
    AndroidPermissionReadInputState,
    AndroidPermissionReadLogs,
    AndroidPermissionReadPhoneState,
    AndroidPermissionReadPrivilegedPhoneState,
    AndroidPermissionReadProfile,
    AndroidPermissionReadSms,
    AndroidPermissionReadSocialStream,
    AndroidPermissionReadSyncSettings,
    AndroidPermissionReadSyncStats,
    AndroidPermissionReadUserDictionary,
    AndroidPermissionReboot,
    AndroidPermissionReceiveBootCompleted,
    AndroidPermissionReceiveDataActivityChange,
    AndroidPermissionReceiveEmergencyBroadcast,
    AndroidPermissionReceiveMms,
    AndroidPermissionReceiveSms,
    AndroidPermissionReceiveWapPush,
    AndroidPermissionRecordAudio,
    AndroidPermissionRemoteAudioPlayback,
    AndroidPermissionRemoveTasks,
    AndroidPermissionReorderTasks,
    AndroidPermissionRequestIgnoreBatteryOptimizations,
    AndroidPermissionRequestInstallPackages,
    AndroidPermissionRestartPackages,
    AndroidPermissionRetrieveWindowContent,
    AndroidPermissionSendRespondViaMessage,
    AndroidPermissionSendSms,
    AndroidPermissionSetAlwaysFinish,
    AndroidPermissionSetAnimationScale,
    AndroidPermissionSetDebugApp,
    AndroidPermissionSetPreferredApplications,
    AndroidPermissionSetProcessLimit,
    AndroidPermissionSetScreenCompatibility,
    AndroidPermissionSetTime,
    AndroidPermissionSetTimeZone,
    AndroidPermissionSetWallpaper,
    AndroidPermissionSetWallpaperComponent,
    AndroidPermissionSetWallpaperHints,
    AndroidPermissionSignalPersistentProcesses,
    AndroidPermissionStartAnyActivity,
    AndroidPermissionStatusBar,
    AndroidPermissionSubscribedFeedsRead,
    AndroidPermissionSystemAlertWindow,
    AndroidPermissionSubscribedFeedsWrite,
    AndroidPermissionTransmitIr,
    AndroidPermissionUpdateDeviceStats,
    AndroidPermissionUseCredentials,
    AndroidPermissionUseFingerprint,
    AndroidPermissionUseSip,
    AndroidPermissionVibrate,
    AndroidPermissionWakeLock,
    AndroidPermissionWriteApnSettings,
    AndroidPermissionWriteCalendar,
    AndroidPermissionWriteCallLog,
    AndroidPermissionWriteContacts,
    AndroidPermissionWriteDreamState,
    AndroidPermissionWriteExternalStorage,
    AndroidPermissionWriteGservices,
    AndroidPermissionWriteMediaStorage,
    AndroidPermissionWriteProfile,
    AndroidPermissionWriteSecureSettings,
    AndroidPermissionWriteSettings,
    AndroidPermissionWriteSms,
    AndroidPermissionWriteSocialStream,
    AndroidPermissionWriteSyncSettings,
    AndroidPermissionWriteUserDictionary,
    ComAndroidAlarmPermissionSetAlarm,
    ComAndroidBrowserPermissionReadHistoryBookmarks,
    ComAndroidBrowserPermissionWriteHistoryBookmarks,
    ComAndroidEmailPermissionReadAttachment,
    ComAndroidLauncherPermissionInstallShortcut,
    ComAndroidLauncherPermissionPreloadWorkspace,
    ComAndroidLauncherPermissionReadSettings,
    ComAndroidLauncherPermissionUninstallShortcut,
    ComAndroidLauncherPermissionWriteSettings,
    ComAndroidVendingCheckLicense,
    ComAndroidVoicemailPermissionAddVoicemail,
    ComAndroidVoicemailPermissionReadVoicemail,
    ComAndroidVoicemailPermissionReadWriteAllVoicemail,
    ComAndroidVoicemailPermissionWriteVoicemail,
    ComGoogleAndroidC2dmPermissionReceive,
    ComGoogleAndroidC2dmPermissionSend,
    ComGoogleAndroidGmsPermissionActivityRecognition,
    ComGoogleAndroidGoogleappsPermissionGoogleAuth,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthAllServices,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthOtherServices,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutubeuser,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthAdsense,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthAdwords,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthAh,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroid,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroidsecure,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthBlogger,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthCl,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthCp,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthDodgeball,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthDoraemon,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthFinance,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthGbase,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthGeowiki,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthGoannaMobile,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthGrandcentral,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthGroups2,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthHealth,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthIg,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthJotspot,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthKnol,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthLh2,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthLocal,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthMail,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthMobile,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthNews,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthNotebook,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthOrkut,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthPanoramio,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthPrint,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthReader,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthSierra,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthSierraqa,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthSierrasandbox,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthSitemaps,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeech,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeechpersonalization,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthTalk,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthWifi,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthWise,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthWritely,
    ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutube,
    ComGoogleAndroidGtalkservicePermissionGtalkService,
    ComGoogleAndroidGtalkservicePermissionSendHeartbeat,
    ComGoogleAndroidPermissionBroadcastDataMessage,
    ComGoogleAndroidProvidersGsfPermissionReadGservices,
    ComGoogleAndroidProvidersTalkPermissionReadOnly,
    ComGoogleAndroidProvidersTalkPermissionWriteOnly,
    ComGoogleAndroidXmppPermissionBroadcast,
    ComGoogleAndroidXmppPermissionSendReceive,
    ComGoogleAndroidXmppPermissionUseXmppEndpoint,
    ComGoogleAndroidXmppPermissionXmppEndpointBroadcast,
}

impl<'de> Deserialize<'de> for Permission {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use failure::Fail;
        use serde::de::Error;

        let result_str: String = serde::Deserialize::deserialize(de)?;

        match Self::from_str(&result_str) {
            Ok(permission) => Ok(permission),
            Err(e) => Err(Error::custom(
                e.context(format!("unknown permission `{}`", result_str)),
            )),
        }
    }
}

impl Permission {
    /// Gets the string representation of the permission.
    #[allow(clippy::too_many_lines)]
    pub fn as_str(&self) -> &str {
        match self {
            Self::AndroidPermissionAccessAllExternalStorage => {
                "android.permission.ACCESS_ALL_EXTERNAL_STORAGE"
            }
            Self::AndroidPermissionAccessCheckinProperties => {
                "android.permission.ACCESS_CHECKIN_PROPERTIES"
            }
            Self::AndroidPermissionAccessCoarseLocation => {
                "android.permission.ACCESS_COARSE_LOCATION"
            }
            Self::AndroidPermissionAccessFineLocation => "android.permission.ACCESS_FINE_LOCATION",
            Self::AndroidPermissionAccessLocationExtraCommands => {
                "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS"
            }
            Self::AndroidPermissionAccessMockLocation => "android.permission.ACCESS_MOCK_LOCATION",
            Self::AndroidPermissionAccessMtp => "android.permission.ACCESS_MTP",
            Self::AndroidPermissionAccessNetworkState => "android.permission.ACCESS_NETWORK_STATE",
            Self::AndroidPermissionAccessNotificationPolicy => {
                "android.permission.ACCESS_NOTIFICATION_POLICY"
            }
            Self::AndroidPermissionAccessWimaxState => "android.permission.ACCESS_WIMAX_STATE",
            Self::AndroidPermissionAccessWifiState => "android.permission.ACCESS_WIFI_STATE",
            Self::AndroidPermissionAccountManager => "android.permission.ACCOUNT_MANAGER",
            Self::AndroidPermissionAsecAccess => "android.permission.ASEC_ACCESS",
            Self::AndroidPermissionAsecCreate => "android.permission.ASEC_CREATE",
            Self::AndroidPermissionAsecDestroy => "android.permission.ASEC_DESTROY",
            Self::AndroidPermissionAsecMountUnmount => "android.permission.ASEC_MOUNT_UNMOUNT",
            Self::AndroidPermissionAsecRename => "android.permission.ASEC_RENAME",
            Self::AndroidPermissionAuthenticateAccounts => {
                "android.permission.AUTHENTICATE_ACCOUNTS"
            }
            Self::AndroidPermissionBatteryStats => "android.permission.BATTERY_STATS",
            Self::AndroidPermissionBindAccessibilityService => {
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            }
            Self::AndroidPermissionBindAppwidget => "android.permission.BIND_APPWIDGET",
            Self::AndroidPermissionBindCallService => "android.permission.BIND_CALL_SERVICE",
            Self::AndroidPermissionBindCarrierMessagingService => {
                "android.permission.BIND_CARRIER_MESSAGING_SERVICE"
            }
            Self::AndroidPermissionBindCarrierServices => {
                "android.permission.BIND_CARRIER_SERVICES"
            }
            Self::AndroidPermissionBindChooserTargetService => {
                "android.permission.BIND_CHOOSER_TARGET_SERVICE"
            }
            Self::AndroidPermissionBindDeviceAdmin => "android.permission.BIND_DEVICE_ADMIN",
            Self::AndroidPermissionBindDirectorySearch => {
                "android.permission.BIND_DIRECTORY_SEARCH"
            }
            Self::AndroidPermissionBindDreamService => "android.permission.BIND_DREAM_SERVICE",
            Self::AndroidPermissionBindIncallService => "android.permission.BIND_INCALL_SERVICE",
            Self::AndroidPermissionBindInputMethod => "android.permission.BIND_INPUT_METHOD",
            Self::AndroidPermissionBindKeyguardAppwidget => {
                "android.permission.BIND_KEYGUARD_APPWIDGET"
            }
            Self::AndroidPermissionBindMidiDeviceService => {
                "android.permission.BIND_MIDI_DEVICE_SERVICE"
            }
            Self::AndroidPermissionBindNfcService => "android.permission.BIND_NFC_SERVICE",
            Self::AndroidPermissionBindNotificationListenerService => {
                "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
            }
            Self::AndroidPermissionBindPrintService => "android.permission.BIND_PRINT_SERVICE",
            Self::AndroidPermissionBindRemoteviews => "android.permission.BIND_REMOTEVIEWS",
            Self::AndroidPermissionBindTelecomConnectionService => {
                "android.permission.BIND_TELECOM_CONNECTION_SERVICE"
            }
            Self::AndroidPermissionBindTextService => "android.permission.BIND_TEXT_SERVICE",
            Self::AndroidPermissionBindTvInput => "android.permission.BIND_TV_INPUT",
            Self::AndroidPermissionBindVoiceInteraction => {
                "android.permission.BIND_VOICE_INTERACTION"
            }
            Self::AndroidPermissionBindVpnService => "android.permission.BIND_VPN_SERVICE",
            Self::AndroidPermissionBindWallpaper => "android.permission.BIND_WALLPAPER",
            Self::AndroidPermissionBluetooth => "android.permission.BLUETOOTH",
            Self::AndroidPermissionBluetoothAdmin => "android.permission.BLUETOOTH_ADMIN",
            Self::AndroidPermissionBluetoothPrivileged => "android.permission.BLUETOOTH_PRIVILEGED",
            Self::AndroidPermissionBluetoothStack => "android.permission.BLUETOOTH_STACK",
            Self::AndroidPermissionBodySensors => "android.permission.BODY_SENSORS",
            Self::AndroidPermissionBroadcastPackageRemoved => {
                "android.permission.BROADCAST_PACKAGE_REMOVED"
            }
            Self::AndroidPermissionBroadcastSms => "android.permission.BROADCAST_SMS",
            Self::AndroidPermissionBroadcastSticky => "android.permission.BROADCAST_STICKY",
            Self::AndroidPermissionBroadcastWapPush => "android.permission.BROADCAST_WAP_PUSH",
            Self::AndroidPermissionCallPhone => "android.permission.CALL_PHONE",
            Self::AndroidPermissionCallPrivileged => "android.permission.CALL_PRIVILEGED",
            Self::AndroidPermissionCamera => "android.permission.CAMERA",
            Self::AndroidPermissionCameraDisableTransmitLed => {
                "android.permission.CAMERA_DISABLE_TRANSMIT_LED"
            }
            Self::AndroidPermissionCaptureAudioOutput => "android.permission.CAPTURE_AUDIO_OUTPUT",
            Self::AndroidPermissionCaptureSecureVideoOutput => {
                "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT"
            }
            Self::AndroidPermissionCaptureVideoOutput => "android.permission.CAPTURE_VIDEO_OUTPUT",
            Self::AndroidPermissionChangeBackgroundDataSetting => {
                "android.permission.CHANGE_BACKGROUND_DATA_SETTING"
            }
            Self::AndroidPermissionChangeComponentEnabledState => {
                "android.permission.CHANGE_COMPONENT_ENABLED_STATE"
            }
            Self::AndroidPermissionChangeConfiguration => "android.permission.CHANGE_CONFIGURATION",
            Self::AndroidPermissionChangeNetworkState => "android.permission.CHANGE_NETWORK_STATE",
            Self::AndroidPermissionChangeWimaxState => "android.permission.CHANGE_WIMAX_STATE",
            Self::AndroidPermissionChangeWifiMulticastState => {
                "android.permission.CHANGE_WIFI_MULTICAST_STATE"
            }
            Self::AndroidPermissionChangeWifiState => "android.permission.CHANGE_WIFI_STATE",
            Self::AndroidPermissionClearAppCache => "android.permission.CLEAR_APP_CACHE",
            Self::AndroidPermissionConnectivityInternal => {
                "android.permission.CONNECTIVITY_INTERNAL"
            }
            Self::AndroidPermissionControlLocationUpdates => {
                "android.permission.CONTROL_LOCATION_UPDATES"
            }
            Self::AndroidPermissionDeleteCacheFiles => "android.permission.DELETE_CACHE_FILES",
            Self::AndroidPermissionDeletePackages => "android.permission.DELETE_PACKAGES",
            Self::AndroidPermissionDiagnostic => "android.permission.DIAGNOSTIC",
            Self::AndroidPermissionDisableKeyguard => "android.permission.DISABLE_KEYGUARD",
            Self::AndroidPermissionDownloadWithoutNotification => {
                "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION"
            }
            Self::AndroidPermissionDump => "android.permission.DUMP",
            Self::AndroidPermissionExpandStatusBar => "android.permission.EXPAND_STATUS_BAR",
            Self::AndroidPermissionFactoryTest => "android.permission.FACTORY_TEST",
            Self::AndroidPermissionFlashlight => "android.permission.FLASHLIGHT",
            Self::AndroidPermissionForceStopPackages => "android.permission.FORCE_STOP_PACKAGES",
            Self::AndroidPermissionGetAccounts => "android.permission.GET_ACCOUNTS",
            Self::AndroidPermissionGetAccountsPrivileged => {
                "android.permission.GET_ACCOUNTS_PRIVILEGED"
            }
            Self::AndroidPermissionGetAppOpsStats => "android.permission.GET_APP_OPS_STATS",
            Self::AndroidPermissionGetDetailedTasks => "android.permission.GET_DETAILED_TASKS",
            Self::AndroidPermissionGetPackageSize => "android.permission.GET_PACKAGE_SIZE",
            Self::AndroidPermissionGetTasks => "android.permission.GET_TASKS",
            Self::AndroidPermissionGlobalSearch => "android.permission.GLOBAL_SEARCH",
            Self::AndroidPermissionGlobalSearchControl => {
                "android.permission.GLOBAL_SEARCH_CONTROL"
            }
            Self::AndroidPermissionHardwareTest => "android.permission.HARDWARE_TEST",
            Self::AndroidPermissionInstallLocationProvider => {
                "android.permission.INSTALL_LOCATION_PROVIDER"
            }
            Self::AndroidPermissionInstallPackages => "android.permission.INSTALL_PACKAGES",
            Self::AndroidPermissionInteractAcrossUsers => {
                "android.permission.INTERACT_ACROSS_USERS"
            }
            Self::AndroidPermissionInteractAcrossUsersFull => {
                "android.permission.INTERACT_ACROSS_USERS_FULL"
            }
            Self::AndroidPermissionInternet => "android.permission.INTERNET",
            Self::AndroidPermissionKillBackgroundProcesses => {
                "android.permission.KILL_BACKGROUND_PROCESSES"
            }
            Self::AndroidPermissionLocationHardware => "android.permission.LOCATION_HARDWARE",
            Self::AndroidPermissionLoopRadio => "android.permission.LOOP_RADIO",
            Self::AndroidPermissionManageAccounts => "android.permission.MANAGE_ACCOUNTS",
            Self::AndroidPermissionManageActivityStacks => {
                "android.permission.MANAGE_ACTIVITY_STACKS"
            }
            Self::AndroidPermissionManageDocuments => "android.permission.MANAGE_DOCUMENTS",
            Self::AndroidPermissionManageUsb => "android.permission.MANAGE_USB",
            Self::AndroidPermissionManageUsers => "android.permission.MANAGE_USERS",
            Self::AndroidPermissionMasterClear => "android.permission.MASTER_CLEAR",
            Self::AndroidPermissionMediaContentControl => {
                "android.permission.MEDIA_CONTENT_CONTROL"
            }
            Self::AndroidPermissionModifyAppwidgetBindPermissions => {
                "android.permission.MODIFY_APPWIDGET_BIND_PERMISSIONS"
            }
            Self::AndroidPermissionModifyAudioSettings => {
                "android.permission.MODIFY_AUDIO_SETTINGS"
            }
            Self::AndroidPermissionModifyPhoneState => "android.permission.MODIFY_PHONE_STATE",
            Self::AndroidPermissionMountFormatFilesystems => {
                "android.permission.MOUNT_FORMAT_FILESYSTEMS"
            }
            Self::AndroidPermissionMountUnmountFilesystems => {
                "android.permission.MOUNT_UNMOUNT_FILESYSTEMS"
            }
            Self::AndroidPermissionNetAdmin => "android.permission.NET_ADMIN",
            Self::AndroidPermissionNetTunneling => "android.permission.NET_TUNNELING",
            Self::AndroidPermissionNfc => "android.permission.NFC",
            Self::AndroidPermissionPackageUsageStats => "android.permission.PACKAGE_USAGE_STATS",
            Self::AndroidPermissionPersistentActivity => "android.permission.PERSISTENT_ACTIVITY",
            Self::AndroidPermissionProcessOutgoingCalls => {
                "android.permission.PROCESS_OUTGOING_CALLS"
            }
            Self::AndroidPermissionReadCalendar => "android.permission.READ_CALENDAR",
            Self::AndroidPermissionReadCallLog => "android.permission.READ_CALL_LOG",
            Self::AndroidPermissionReadCellBroadcasts => "android.permission.READ_CELL_BROADCASTS",
            Self::AndroidPermissionReadContacts => "android.permission.READ_CONTACTS",
            Self::AndroidPermissionReadDreamState => "android.permission.READ_DREAM_STATE",
            Self::AndroidPermissionReadExternalStorage => {
                "android.permission.READ_EXTERNAL_STORAGE"
            }
            Self::AndroidPermissionReadFrameBuffer => "android.permission.READ_FRAME_BUFFER",
            Self::AndroidPermissionReadInputState => "android.permission.READ_INPUT_STATE",
            Self::AndroidPermissionReadLogs => "android.permission.READ_LOGS",
            Self::AndroidPermissionReadPhoneState => "android.permission.READ_PHONE_STATE",
            Self::AndroidPermissionReadPrivilegedPhoneState => {
                "android.permission.READ_PRIVILEGED_PHONE_STATE"
            }
            Self::AndroidPermissionReadProfile => "android.permission.READ_PROFILE",
            Self::AndroidPermissionReadSms => "android.permission.READ_SMS",
            Self::AndroidPermissionReadSocialStream => "android.permission.READ_SOCIAL_STREAM",
            Self::AndroidPermissionReadSyncSettings => "android.permission.READ_SYNC_SETTINGS",
            Self::AndroidPermissionReadSyncStats => "android.permission.READ_SYNC_STATS",
            Self::AndroidPermissionReadUserDictionary => "android.permission.READ_USER_DICTIONARY",
            Self::AndroidPermissionReboot => "android.permission.REBOOT",
            Self::AndroidPermissionReceiveBootCompleted => {
                "android.permission.RECEIVE_BOOT_COMPLETED"
            }
            Self::AndroidPermissionReceiveDataActivityChange => {
                "android.permission.RECEIVE_DATA_ACTIVITY_CHANGE"
            }
            Self::AndroidPermissionReceiveEmergencyBroadcast => {
                "android.permission.RECEIVE_EMERGENCY_BROADCAST"
            }
            Self::AndroidPermissionReceiveMms => "android.permission.RECEIVE_MMS",
            Self::AndroidPermissionReceiveSms => "android.permission.RECEIVE_SMS",
            Self::AndroidPermissionReceiveWapPush => "android.permission.RECEIVE_WAP_PUSH",
            Self::AndroidPermissionRecordAudio => "android.permission.RECORD_AUDIO",
            Self::AndroidPermissionRemoteAudioPlayback => {
                "android.permission.REMOTE_AUDIO_PLAYBACK"
            }
            Self::AndroidPermissionRemoveTasks => "android.permission.REMOVE_TASKS",
            Self::AndroidPermissionReorderTasks => "android.permission.REORDER_TASKS",
            Self::AndroidPermissionRequestIgnoreBatteryOptimizations => {
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
            }
            Self::AndroidPermissionRequestInstallPackages => {
                "android.permission.REQUEST_INSTALL_PACKAGES"
            }
            Self::AndroidPermissionRestartPackages => "android.permission.RESTART_PACKAGES",
            Self::AndroidPermissionRetrieveWindowContent => {
                "android.permission.RETRIEVE_WINDOW_CONTENT"
            }
            Self::AndroidPermissionSendRespondViaMessage => {
                "android.permission.SEND_RESPOND_VIA_MESSAGE"
            }
            Self::AndroidPermissionSendSms => "android.permission.SEND_SMS",
            Self::AndroidPermissionSetAlwaysFinish => "android.permission.SET_ALWAYS_FINISH",
            Self::AndroidPermissionSetAnimationScale => "android.permission.SET_ANIMATION_SCALE",
            Self::AndroidPermissionSetDebugApp => "android.permission.SET_DEBUG_APP",
            Self::AndroidPermissionSetPreferredApplications => {
                "android.permission.SET_PREFERRED_APPLICATIONS"
            }
            Self::AndroidPermissionSetProcessLimit => "android.permission.SET_PROCESS_LIMIT",
            Self::AndroidPermissionSetScreenCompatibility => {
                "android.permission.SET_SCREEN_COMPATIBILITY"
            }
            Self::AndroidPermissionSetTime => "android.permission.SET_TIME",
            Self::AndroidPermissionSetTimeZone => "android.permission.SET_TIME_ZONE",
            Self::AndroidPermissionSetWallpaper => "android.permission.SET_WALLPAPER",
            Self::AndroidPermissionSetWallpaperComponent => {
                "android.permission.SET_WALLPAPER_COMPONENT"
            }
            Self::AndroidPermissionSetWallpaperHints => "android.permission.SET_WALLPAPER_HINTS",
            Self::AndroidPermissionSignalPersistentProcesses => {
                "android.permission.SIGNAL_PERSISTENT_PROCESSES"
            }
            Self::AndroidPermissionStartAnyActivity => "android.permission.START_ANY_ACTIVITY",
            Self::AndroidPermissionStatusBar => "android.permission.STATUS_BAR",
            Self::AndroidPermissionSubscribedFeedsRead => {
                "android.permission.SUBSCRIBED_FEEDS_READ"
            }
            Self::AndroidPermissionSystemAlertWindow => "android.permission.SYSTEM_ALERT_WINDOW",
            Self::AndroidPermissionSubscribedFeedsWrite => {
                "android.permission.SUBSCRIBED_FEEDS_WRITE"
            }
            Self::AndroidPermissionTransmitIr => "android.permission.TRANSMIT_IR",
            Self::AndroidPermissionUpdateDeviceStats => "android.permission.UPDATE_DEVICE_STATS",
            Self::AndroidPermissionUseCredentials => "android.permission.USE_CREDENTIALS",
            Self::AndroidPermissionUseFingerprint => "android.permission.USE_FINGERPRINT",
            Self::AndroidPermissionUseSip => "android.permission.USE_SIP",
            Self::AndroidPermissionVibrate => "android.permission.VIBRATE",
            Self::AndroidPermissionWakeLock => "android.permission.WAKE_LOCK",
            Self::AndroidPermissionWriteApnSettings => "android.permission.WRITE_APN_SETTINGS",
            Self::AndroidPermissionWriteCalendar => "android.permission.WRITE_CALENDAR",
            Self::AndroidPermissionWriteCallLog => "android.permission.WRITE_CALL_LOG",
            Self::AndroidPermissionWriteContacts => "android.permission.WRITE_CONTACTS",
            Self::AndroidPermissionWriteDreamState => "android.permission.WRITE_DREAM_STATE",
            Self::AndroidPermissionWriteExternalStorage => {
                "android.permission.WRITE_EXTERNAL_STORAGE"
            }
            Self::AndroidPermissionWriteGservices => "android.permission.WRITE_GSERVICES",
            Self::AndroidPermissionWriteMediaStorage => "android.permission.WRITE_MEDIA_STORAGE",
            Self::AndroidPermissionWriteProfile => "android.permission.WRITE_PROFILE",
            Self::AndroidPermissionWriteSecureSettings => {
                "android.permission.WRITE_SECURE_SETTINGS"
            }
            Self::AndroidPermissionWriteSettings => "android.permission.WRITE_SETTINGS",
            Self::AndroidPermissionWriteSms => "android.permission.WRITE_SMS",
            Self::AndroidPermissionWriteSocialStream => "android.permission.WRITE_SOCIAL_STREAM",
            Self::AndroidPermissionWriteSyncSettings => "android.permission.WRITE_SYNC_SETTINGS",
            Self::AndroidPermissionWriteUserDictionary => {
                "android.permission.WRITE_USER_DICTIONARY"
            }
            Self::ComAndroidAlarmPermissionSetAlarm => "com.android.alarm.permission.SET_ALARM",
            Self::ComAndroidBrowserPermissionReadHistoryBookmarks => {
                "com.android.browser.permission.READ_HISTORY_BOOKMARKS"
            }
            Self::ComAndroidBrowserPermissionWriteHistoryBookmarks => {
                "com.android.browser.permission.WRITE_HISTORY_BOOKMARKS"
            }
            Self::ComAndroidEmailPermissionReadAttachment => {
                "com.android.email.permission.READ_ATTACHMENT"
            }
            Self::ComAndroidLauncherPermissionInstallShortcut => {
                "com.android.launcher.permission.INSTALL_SHORTCUT"
            }
            Self::ComAndroidLauncherPermissionPreloadWorkspace => {
                "com.android.launcher.permission.PRELOAD_WORKSPACE"
            }
            Self::ComAndroidLauncherPermissionReadSettings => {
                "com.android.launcher.permission.READ_SETTINGS"
            }
            Self::ComAndroidLauncherPermissionUninstallShortcut => {
                "com.android.launcher.permission.UNINSTALL_SHORTCUT"
            }
            Self::ComAndroidLauncherPermissionWriteSettings => {
                "com.android.launcher.permission.WRITE_SETTINGS"
            }
            Self::ComAndroidVendingCheckLicense => "com.android.vending.CHECK_LICENSE",
            Self::ComAndroidVoicemailPermissionAddVoicemail => {
                "com.android.voicemail.permission.ADD_VOICEMAIL"
            }
            Self::ComAndroidVoicemailPermissionReadVoicemail => {
                "com.android.voicemail.permission.READ_VOICEMAIL"
            }
            Self::ComAndroidVoicemailPermissionReadWriteAllVoicemail => {
                "com.android.voicemail.permission.READ_WRITE_ALL_VOICEMAIL"
            }
            Self::ComAndroidVoicemailPermissionWriteVoicemail => {
                "com.android.voicemail.permission.WRITE_VOICEMAIL"
            }
            Self::ComGoogleAndroidC2dmPermissionReceive => {
                "com.google.android.c2dm.permission.RECEIVE"
            }
            Self::ComGoogleAndroidC2dmPermissionSend => "com.google.android.c2dm.permission.SEND",
            Self::ComGoogleAndroidGmsPermissionActivityRecognition => {
                "com.google.android.gms.permission.ACTIVITY_RECOGNITION"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuth => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAllServices => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.ALL_SERVICES"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthOtherServices => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.OTHER_SERVICES"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutubeuser => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.YouTubeUser"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAdsense => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.adsense"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAdwords => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.adwords"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAh => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.ah"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroid => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.android"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroidsecure => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.androidsecure"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthBlogger => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.blogger"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthCl => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.cl"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthCp => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.cp"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthDodgeball => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.dodgeball"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthDoraemon => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.doraemon"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthFinance => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.finance"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGbase => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.gbase"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGeowiki => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.geowiki"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGoannaMobile => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.goanna_mobile"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGrandcentral => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.grandcentral"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGroups2 => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.groups2"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthHealth => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.health"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthIg => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.ig"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthJotspot => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.jotspot"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthKnol => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.knol"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthLh2 => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.lh2"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthLocal => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.local"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthMail => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.mail"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthMobile => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.mobile"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthNews => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.news"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthNotebook => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.notebook"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthOrkut => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.orkut"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthPanoramio => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.panoramio"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthPrint => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.print"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthReader => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.reader"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierra => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.sierra"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierraqa => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.sierraqa"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierrasandbox => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.sierrasandbox"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSitemaps => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.sitemaps"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeech => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.speech"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeechpersonalization => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.speechpersonalization"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthTalk => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.talk"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthWifi => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.wifi"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthWise => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.wise"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthWritely => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.writely"
            }
            Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutube => {
                "com.google.android.googleapps.permission.GOOGLE_AUTH.youtube"
            }
            Self::ComGoogleAndroidGtalkservicePermissionGtalkService => {
                "com.google.android.gtalkservice.permission.GTALK_SERVICE"
            }
            Self::ComGoogleAndroidGtalkservicePermissionSendHeartbeat => {
                "com.google.android.gtalkservice.permission.SEND_HEARTBEAT"
            }
            Self::ComGoogleAndroidPermissionBroadcastDataMessage => {
                "com.google.android.permission.BROADCAST_DATA_MESSAGE"
            }
            Self::ComGoogleAndroidProvidersGsfPermissionReadGservices => {
                "com.google.android.providers.gsf.permission.READ_GSERVICES"
            }
            Self::ComGoogleAndroidProvidersTalkPermissionReadOnly => {
                "com.google.android.providers.talk.permission.READ_ONLY"
            }
            Self::ComGoogleAndroidProvidersTalkPermissionWriteOnly => {
                "com.google.android.providers.talk.permission.WRITE_ONLY"
            }
            Self::ComGoogleAndroidXmppPermissionBroadcast => {
                "com.google.android.xmpp.permission.BROADCAST"
            }
            Self::ComGoogleAndroidXmppPermissionSendReceive => {
                "com.google.android.xmpp.permission.SEND_RECEIVE"
            }
            Self::ComGoogleAndroidXmppPermissionUseXmppEndpoint => {
                "com.google.android.xmpp.permission.USE_XMPP_ENDPOINT"
            }
            Self::ComGoogleAndroidXmppPermissionXmppEndpointBroadcast => {
                "com.google.android.xmpp.permission.XMPP_ENDPOINT_BROADCAST"
            }
        }
    }
}

impl FromStr for Permission {
    type Err = ErrorKind;

    #[allow(clippy::too_many_lines)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "android.permission.ACCESS_ALL_EXTERNAL_STORAGE" => {
                Ok(Self::AndroidPermissionAccessAllExternalStorage)
            }
            "android.permission.ACCESS_CHECKIN_PROPERTIES" => {
                Ok(Self::AndroidPermissionAccessCheckinProperties)
            }
            "android.permission.ACCESS_COARSE_LOCATION" => {
                Ok(Self::AndroidPermissionAccessCoarseLocation)
            }
            "android.permission.ACCESS_FINE_LOCATION" => {
                Ok(Self::AndroidPermissionAccessFineLocation)
            }
            "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS" => {
                Ok(Self::AndroidPermissionAccessLocationExtraCommands)
            }
            "android.permission.ACCESS_MOCK_LOCATION" => {
                Ok(Self::AndroidPermissionAccessMockLocation)
            }
            "android.permission.ACCESS_MTP" => Ok(Self::AndroidPermissionAccessMtp),
            "android.permission.ACCESS_NETWORK_STATE" => {
                Ok(Self::AndroidPermissionAccessNetworkState)
            }
            "android.permission.ACCESS_NOTIFICATION_POLICY" => {
                Ok(Self::AndroidPermissionAccessNotificationPolicy)
            }
            "android.permission.ACCESS_WIMAX_STATE" => Ok(Self::AndroidPermissionAccessWimaxState),
            "android.permission.ACCESS_WIFI_STATE" => Ok(Self::AndroidPermissionAccessWifiState),
            "android.permission.ACCOUNT_MANAGER" => Ok(Self::AndroidPermissionAccountManager),
            "android.permission.ASEC_ACCESS" => Ok(Self::AndroidPermissionAsecAccess),
            "android.permission.ASEC_CREATE" => Ok(Self::AndroidPermissionAsecCreate),
            "android.permission.ASEC_DESTROY" => Ok(Self::AndroidPermissionAsecDestroy),
            "android.permission.ASEC_MOUNT_UNMOUNT" => Ok(Self::AndroidPermissionAsecMountUnmount),
            "android.permission.ASEC_RENAME" => Ok(Self::AndroidPermissionAsecRename),
            "android.permission.AUTHENTICATE_ACCOUNTS" => {
                Ok(Self::AndroidPermissionAuthenticateAccounts)
            }
            "android.permission.BATTERY_STATS" => Ok(Self::AndroidPermissionBatteryStats),
            "android.permission.BIND_ACCESSIBILITY_SERVICE" => {
                Ok(Self::AndroidPermissionBindAccessibilityService)
            }
            "android.permission.BIND_APPWIDGET" => Ok(Self::AndroidPermissionBindAppwidget),
            "android.permission.BIND_CALL_SERVICE" => Ok(Self::AndroidPermissionBindCallService),
            "android.permission.BIND_CARRIER_MESSAGING_SERVICE" => {
                Ok(Self::AndroidPermissionBindCarrierMessagingService)
            }
            "android.permission.BIND_CARRIER_SERVICES" => {
                Ok(Self::AndroidPermissionBindCarrierServices)
            }
            "android.permission.BIND_CHOOSER_TARGET_SERVICE" => {
                Ok(Self::AndroidPermissionBindChooserTargetService)
            }
            "android.permission.BIND_DEVICE_ADMIN" => Ok(Self::AndroidPermissionBindDeviceAdmin),
            "android.permission.BIND_DIRECTORY_SEARCH" => {
                Ok(Self::AndroidPermissionBindDirectorySearch)
            }
            "android.permission.BIND_DREAM_SERVICE" => Ok(Self::AndroidPermissionBindDreamService),
            "android.permission.BIND_INCALL_SERVICE" => {
                Ok(Self::AndroidPermissionBindIncallService)
            }
            "android.permission.BIND_INPUT_METHOD" => Ok(Self::AndroidPermissionBindInputMethod),
            "android.permission.BIND_KEYGUARD_APPWIDGET" => {
                Ok(Self::AndroidPermissionBindKeyguardAppwidget)
            }
            "android.permission.BIND_MIDI_DEVICE_SERVICE" => {
                Ok(Self::AndroidPermissionBindMidiDeviceService)
            }
            "android.permission.BIND_NFC_SERVICE" => Ok(Self::AndroidPermissionBindNfcService),
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" => {
                Ok(Self::AndroidPermissionBindNotificationListenerService)
            }
            "android.permission.BIND_PRINT_SERVICE" => Ok(Self::AndroidPermissionBindPrintService),
            "android.permission.BIND_REMOTEVIEWS" => Ok(Self::AndroidPermissionBindRemoteviews),
            "android.permission.BIND_TELECOM_CONNECTION_SERVICE" => {
                Ok(Self::AndroidPermissionBindTelecomConnectionService)
            }
            "android.permission.BIND_TEXT_SERVICE" => Ok(Self::AndroidPermissionBindTextService),
            "android.permission.BIND_TV_INPUT" => Ok(Self::AndroidPermissionBindTvInput),
            "android.permission.BIND_VOICE_INTERACTION" => {
                Ok(Self::AndroidPermissionBindVoiceInteraction)
            }
            "android.permission.BIND_VPN_SERVICE" => Ok(Self::AndroidPermissionBindVpnService),
            "android.permission.BIND_WALLPAPER" => Ok(Self::AndroidPermissionBindWallpaper),
            "android.permission.BLUETOOTH" => Ok(Self::AndroidPermissionBluetooth),
            "android.permission.BLUETOOTH_ADMIN" => Ok(Self::AndroidPermissionBluetoothAdmin),
            "android.permission.BLUETOOTH_PRIVILEGED" => {
                Ok(Self::AndroidPermissionBluetoothPrivileged)
            }
            "android.permission.BLUETOOTH_STACK" => Ok(Self::AndroidPermissionBluetoothStack),
            "android.permission.BODY_SENSORS" => Ok(Self::AndroidPermissionBodySensors),
            "android.permission.BROADCAST_PACKAGE_REMOVED" => {
                Ok(Self::AndroidPermissionBroadcastPackageRemoved)
            }
            "android.permission.BROADCAST_SMS" => Ok(Self::AndroidPermissionBroadcastSms),
            "android.permission.BROADCAST_STICKY" => Ok(Self::AndroidPermissionBroadcastSticky),
            "android.permission.BROADCAST_WAP_PUSH" => Ok(Self::AndroidPermissionBroadcastWapPush),
            "android.permission.CALL_PHONE" => Ok(Self::AndroidPermissionCallPhone),
            "android.permission.CALL_PRIVILEGED" => Ok(Self::AndroidPermissionCallPrivileged),
            "android.permission.CAMERA" => Ok(Self::AndroidPermissionCamera),
            "android.permission.CAMERA_DISABLE_TRANSMIT_LED" => {
                Ok(Self::AndroidPermissionCameraDisableTransmitLed)
            }
            "android.permission.CAPTURE_AUDIO_OUTPUT" => {
                Ok(Self::AndroidPermissionCaptureAudioOutput)
            }
            "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT" => {
                Ok(Self::AndroidPermissionCaptureSecureVideoOutput)
            }
            "android.permission.CAPTURE_VIDEO_OUTPUT" => {
                Ok(Self::AndroidPermissionCaptureVideoOutput)
            }
            "android.permission.CHANGE_BACKGROUND_DATA_SETTING" => {
                Ok(Self::AndroidPermissionChangeBackgroundDataSetting)
            }
            "android.permission.CHANGE_COMPONENT_ENABLED_STATE" => {
                Ok(Self::AndroidPermissionChangeComponentEnabledState)
            }
            "android.permission.CHANGE_CONFIGURATION" => {
                Ok(Self::AndroidPermissionChangeConfiguration)
            }
            "android.permission.CHANGE_NETWORK_STATE" => {
                Ok(Self::AndroidPermissionChangeNetworkState)
            }
            "android.permission.CHANGE_WIMAX_STATE" => Ok(Self::AndroidPermissionChangeWimaxState),
            "android.permission.CHANGE_WIFI_MULTICAST_STATE" => {
                Ok(Self::AndroidPermissionChangeWifiMulticastState)
            }
            "android.permission.CHANGE_WIFI_STATE" => Ok(Self::AndroidPermissionChangeWifiState),
            "android.permission.CLEAR_APP_CACHE" => Ok(Self::AndroidPermissionClearAppCache),
            "android.permission.CONNECTIVITY_INTERNAL" => {
                Ok(Self::AndroidPermissionConnectivityInternal)
            }
            "android.permission.CONTROL_LOCATION_UPDATES" => {
                Ok(Self::AndroidPermissionControlLocationUpdates)
            }
            "android.permission.DELETE_CACHE_FILES" => Ok(Self::AndroidPermissionDeleteCacheFiles),
            "android.permission.DELETE_PACKAGES" => Ok(Self::AndroidPermissionDeletePackages),
            "android.permission.DIAGNOSTIC" => Ok(Self::AndroidPermissionDiagnostic),
            "android.permission.DISABLE_KEYGUARD" => Ok(Self::AndroidPermissionDisableKeyguard),
            "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION" => {
                Ok(Self::AndroidPermissionDownloadWithoutNotification)
            }
            "android.permission.DUMP" => Ok(Self::AndroidPermissionDump),
            "android.permission.EXPAND_STATUS_BAR" => Ok(Self::AndroidPermissionExpandStatusBar),
            "android.permission.FACTORY_TEST" => Ok(Self::AndroidPermissionFactoryTest),
            "android.permission.FLASHLIGHT" => Ok(Self::AndroidPermissionFlashlight),
            "android.permission.FORCE_STOP_PACKAGES" => {
                Ok(Self::AndroidPermissionForceStopPackages)
            }
            "android.permission.GET_ACCOUNTS" => Ok(Self::AndroidPermissionGetAccounts),
            "android.permission.GET_ACCOUNTS_PRIVILEGED" => {
                Ok(Self::AndroidPermissionGetAccountsPrivileged)
            }
            "android.permission.GET_APP_OPS_STATS" => Ok(Self::AndroidPermissionGetAppOpsStats),
            "android.permission.GET_DETAILED_TASKS" => Ok(Self::AndroidPermissionGetDetailedTasks),
            "android.permission.GET_PACKAGE_SIZE" => Ok(Self::AndroidPermissionGetPackageSize),
            "android.permission.GET_TASKS" => Ok(Self::AndroidPermissionGetTasks),
            "android.permission.GLOBAL_SEARCH" => Ok(Self::AndroidPermissionGlobalSearch),
            "android.permission.GLOBAL_SEARCH_CONTROL" => {
                Ok(Self::AndroidPermissionGlobalSearchControl)
            }
            "android.permission.HARDWARE_TEST" => Ok(Self::AndroidPermissionHardwareTest),
            "android.permission.INSTALL_LOCATION_PROVIDER" => {
                Ok(Self::AndroidPermissionInstallLocationProvider)
            }
            "android.permission.INSTALL_PACKAGES" => Ok(Self::AndroidPermissionInstallPackages),
            "android.permission.INTERACT_ACROSS_USERS" => {
                Ok(Self::AndroidPermissionInteractAcrossUsers)
            }
            "android.permission.INTERACT_ACROSS_USERS_FULL" => {
                Ok(Self::AndroidPermissionInteractAcrossUsersFull)
            }
            "android.permission.INTERNET" => Ok(Self::AndroidPermissionInternet),
            "android.permission.KILL_BACKGROUND_PROCESSES" => {
                Ok(Self::AndroidPermissionKillBackgroundProcesses)
            }
            "android.permission.LOCATION_HARDWARE" => Ok(Self::AndroidPermissionLocationHardware),
            "android.permission.LOOP_RADIO" => Ok(Self::AndroidPermissionLoopRadio),
            "android.permission.MANAGE_ACCOUNTS" => Ok(Self::AndroidPermissionManageAccounts),
            "android.permission.MANAGE_ACTIVITY_STACKS" => {
                Ok(Self::AndroidPermissionManageActivityStacks)
            }
            "android.permission.MANAGE_DOCUMENTS" => Ok(Self::AndroidPermissionManageDocuments),
            "android.permission.MANAGE_USB" => Ok(Self::AndroidPermissionManageUsb),
            "android.permission.MANAGE_USERS" => Ok(Self::AndroidPermissionManageUsers),
            "android.permission.MASTER_CLEAR" => Ok(Self::AndroidPermissionMasterClear),
            "android.permission.MEDIA_CONTENT_CONTROL" => {
                Ok(Self::AndroidPermissionMediaContentControl)
            }
            "android.permission.MODIFY_APPWIDGET_BIND_PERMISSIONS" => {
                Ok(Self::AndroidPermissionModifyAppwidgetBindPermissions)
            }
            "android.permission.MODIFY_AUDIO_SETTINGS" => {
                Ok(Self::AndroidPermissionModifyAudioSettings)
            }
            "android.permission.MODIFY_PHONE_STATE" => Ok(Self::AndroidPermissionModifyPhoneState),
            "android.permission.MOUNT_FORMAT_FILESYSTEMS" => {
                Ok(Self::AndroidPermissionMountFormatFilesystems)
            }
            "android.permission.MOUNT_UNMOUNT_FILESYSTEMS" => {
                Ok(Self::AndroidPermissionMountUnmountFilesystems)
            }
            "android.permission.NET_ADMIN" => Ok(Self::AndroidPermissionNetAdmin),
            "android.permission.NET_TUNNELING" => Ok(Self::AndroidPermissionNetTunneling),
            "android.permission.NFC" => Ok(Self::AndroidPermissionNfc),
            "android.permission.PACKAGE_USAGE_STATS" => {
                Ok(Self::AndroidPermissionPackageUsageStats)
            }
            "android.permission.PERSISTENT_ACTIVITY" => {
                Ok(Self::AndroidPermissionPersistentActivity)
            }
            "android.permission.PROCESS_OUTGOING_CALLS" => {
                Ok(Self::AndroidPermissionProcessOutgoingCalls)
            }
            "android.permission.READ_CALENDAR" => Ok(Self::AndroidPermissionReadCalendar),
            "android.permission.READ_CALL_LOG" => Ok(Self::AndroidPermissionReadCallLog),
            "android.permission.READ_CELL_BROADCASTS" => {
                Ok(Self::AndroidPermissionReadCellBroadcasts)
            }
            "android.permission.READ_CONTACTS" => Ok(Self::AndroidPermissionReadContacts),
            "android.permission.READ_DREAM_STATE" => Ok(Self::AndroidPermissionReadDreamState),
            "android.permission.READ_EXTERNAL_STORAGE" => {
                Ok(Self::AndroidPermissionReadExternalStorage)
            }
            "android.permission.READ_FRAME_BUFFER" => Ok(Self::AndroidPermissionReadFrameBuffer),
            "android.permission.READ_INPUT_STATE" => Ok(Self::AndroidPermissionReadInputState),
            "android.permission.READ_LOGS" => Ok(Self::AndroidPermissionReadLogs),
            "android.permission.READ_PHONE_STATE" => Ok(Self::AndroidPermissionReadPhoneState),
            "android.permission.READ_PRIVILEGED_PHONE_STATE" => {
                Ok(Self::AndroidPermissionReadPrivilegedPhoneState)
            }
            "android.permission.READ_PROFILE" => Ok(Self::AndroidPermissionReadProfile),
            "android.permission.READ_SMS" => Ok(Self::AndroidPermissionReadSms),
            "android.permission.READ_SOCIAL_STREAM" => Ok(Self::AndroidPermissionReadSocialStream),
            "android.permission.READ_SYNC_SETTINGS" => Ok(Self::AndroidPermissionReadSyncSettings),
            "android.permission.READ_SYNC_STATS" => Ok(Self::AndroidPermissionReadSyncStats),
            "android.permission.READ_USER_DICTIONARY" => {
                Ok(Self::AndroidPermissionReadUserDictionary)
            }
            "android.permission.REBOOT" => Ok(Self::AndroidPermissionReboot),
            "android.permission.RECEIVE_BOOT_COMPLETED" => {
                Ok(Self::AndroidPermissionReceiveBootCompleted)
            }
            "android.permission.RECEIVE_DATA_ACTIVITY_CHANGE" => {
                Ok(Self::AndroidPermissionReceiveDataActivityChange)
            }
            "android.permission.RECEIVE_EMERGENCY_BROADCAST" => {
                Ok(Self::AndroidPermissionReceiveEmergencyBroadcast)
            }
            "android.permission.RECEIVE_MMS" => Ok(Self::AndroidPermissionReceiveMms),
            "android.permission.RECEIVE_SMS" => Ok(Self::AndroidPermissionReceiveSms),
            "android.permission.RECEIVE_WAP_PUSH" => Ok(Self::AndroidPermissionReceiveWapPush),
            "android.permission.RECORD_AUDIO" => Ok(Self::AndroidPermissionRecordAudio),
            "android.permission.REMOTE_AUDIO_PLAYBACK" => {
                Ok(Self::AndroidPermissionRemoteAudioPlayback)
            }
            "android.permission.REMOVE_TASKS" => Ok(Self::AndroidPermissionRemoveTasks),
            "android.permission.REORDER_TASKS" => Ok(Self::AndroidPermissionReorderTasks),
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" => {
                Ok(Self::AndroidPermissionRequestIgnoreBatteryOptimizations)
            }
            "android.permission.REQUEST_INSTALL_PACKAGES" => {
                Ok(Self::AndroidPermissionRequestInstallPackages)
            }
            "android.permission.RESTART_PACKAGES" => Ok(Self::AndroidPermissionRestartPackages),
            "android.permission.RETRIEVE_WINDOW_CONTENT" => {
                Ok(Self::AndroidPermissionRetrieveWindowContent)
            }
            "android.permission.SEND_RESPOND_VIA_MESSAGE" => {
                Ok(Self::AndroidPermissionSendRespondViaMessage)
            }
            "android.permission.SEND_SMS" => Ok(Self::AndroidPermissionSendSms),
            "android.permission.SET_ALWAYS_FINISH" => Ok(Self::AndroidPermissionSetAlwaysFinish),
            "android.permission.SET_ANIMATION_SCALE" => {
                Ok(Self::AndroidPermissionSetAnimationScale)
            }
            "android.permission.SET_DEBUG_APP" => Ok(Self::AndroidPermissionSetDebugApp),
            "android.permission.SET_PREFERRED_APPLICATIONS" => {
                Ok(Self::AndroidPermissionSetPreferredApplications)
            }
            "android.permission.SET_PROCESS_LIMIT" => Ok(Self::AndroidPermissionSetProcessLimit),
            "android.permission.SET_SCREEN_COMPATIBILITY" => {
                Ok(Self::AndroidPermissionSetScreenCompatibility)
            }
            "android.permission.SET_TIME" => Ok(Self::AndroidPermissionSetTime),
            "android.permission.SET_TIME_ZONE" => Ok(Self::AndroidPermissionSetTimeZone),
            "android.permission.SET_WALLPAPER" => Ok(Self::AndroidPermissionSetWallpaper),
            "android.permission.SET_WALLPAPER_COMPONENT" => {
                Ok(Self::AndroidPermissionSetWallpaperComponent)
            }
            "android.permission.SET_WALLPAPER_HINTS" => {
                Ok(Self::AndroidPermissionSetWallpaperHints)
            }
            "android.permission.SIGNAL_PERSISTENT_PROCESSES" => {
                Ok(Self::AndroidPermissionSignalPersistentProcesses)
            }
            "android.permission.START_ANY_ACTIVITY" => Ok(Self::AndroidPermissionStartAnyActivity),
            "android.permission.STATUS_BAR" => Ok(Self::AndroidPermissionStatusBar),
            "android.permission.SUBSCRIBED_FEEDS_READ" => {
                Ok(Self::AndroidPermissionSubscribedFeedsRead)
            }
            "android.permission.SYSTEM_ALERT_WINDOW" => {
                Ok(Self::AndroidPermissionSystemAlertWindow)
            }
            "android.permission.SUBSCRIBED_FEEDS_WRITE" => {
                Ok(Self::AndroidPermissionSubscribedFeedsWrite)
            }
            "android.permission.TRANSMIT_IR" => Ok(Self::AndroidPermissionTransmitIr),
            "android.permission.UPDATE_DEVICE_STATS" => {
                Ok(Self::AndroidPermissionUpdateDeviceStats)
            }
            "android.permission.USE_CREDENTIALS" => Ok(Self::AndroidPermissionUseCredentials),
            "android.permission.USE_FINGERPRINT" => Ok(Self::AndroidPermissionUseFingerprint),
            "android.permission.USE_SIP" => Ok(Self::AndroidPermissionUseSip),
            "android.permission.VIBRATE" => Ok(Self::AndroidPermissionVibrate),
            "android.permission.WAKE_LOCK" => Ok(Self::AndroidPermissionWakeLock),
            "android.permission.WRITE_APN_SETTINGS" => Ok(Self::AndroidPermissionWriteApnSettings),
            "android.permission.WRITE_CALENDAR" => Ok(Self::AndroidPermissionWriteCalendar),
            "android.permission.WRITE_CALL_LOG" => Ok(Self::AndroidPermissionWriteCallLog),
            "android.permission.WRITE_CONTACTS" => Ok(Self::AndroidPermissionWriteContacts),
            "android.permission.WRITE_DREAM_STATE" => Ok(Self::AndroidPermissionWriteDreamState),
            "android.permission.WRITE_EXTERNAL_STORAGE" => {
                Ok(Self::AndroidPermissionWriteExternalStorage)
            }
            "android.permission.WRITE_GSERVICES" => Ok(Self::AndroidPermissionWriteGservices),
            "android.permission.WRITE_MEDIA_STORAGE" => {
                Ok(Self::AndroidPermissionWriteMediaStorage)
            }
            "android.permission.WRITE_PROFILE" => Ok(Self::AndroidPermissionWriteProfile),
            "android.permission.WRITE_SECURE_SETTINGS" => {
                Ok(Self::AndroidPermissionWriteSecureSettings)
            }
            "android.permission.WRITE_SETTINGS" => Ok(Self::AndroidPermissionWriteSettings),
            "android.permission.WRITE_SMS" => Ok(Self::AndroidPermissionWriteSms),
            "android.permission.WRITE_SOCIAL_STREAM" => {
                Ok(Self::AndroidPermissionWriteSocialStream)
            }
            "android.permission.WRITE_SYNC_SETTINGS" => {
                Ok(Self::AndroidPermissionWriteSyncSettings)
            }
            "android.permission.WRITE_USER_DICTIONARY" => {
                Ok(Self::AndroidPermissionWriteUserDictionary)
            }
            "com.android.alarm.permission.SET_ALARM" => Ok(Self::ComAndroidAlarmPermissionSetAlarm),
            "com.android.browser.permission.READ_HISTORY_BOOKMARKS" => {
                Ok(Self::ComAndroidBrowserPermissionReadHistoryBookmarks)
            }
            "com.android.browser.permission.WRITE_HISTORY_BOOKMARKS" => {
                Ok(Self::ComAndroidBrowserPermissionWriteHistoryBookmarks)
            }
            "com.android.email.permission.READ_ATTACHMENT" => {
                Ok(Self::ComAndroidEmailPermissionReadAttachment)
            }
            "com.android.launcher.permission.INSTALL_SHORTCUT" => {
                Ok(Self::ComAndroidLauncherPermissionInstallShortcut)
            }
            "com.android.launcher.permission.PRELOAD_WORKSPACE" => {
                Ok(Self::ComAndroidLauncherPermissionPreloadWorkspace)
            }
            "com.android.launcher.permission.READ_SETTINGS" => {
                Ok(Self::ComAndroidLauncherPermissionReadSettings)
            }
            "com.android.launcher.permission.UNINSTALL_SHORTCUT" => {
                Ok(Self::ComAndroidLauncherPermissionUninstallShortcut)
            }
            "com.android.launcher.permission.WRITE_SETTINGS" => {
                Ok(Self::ComAndroidLauncherPermissionWriteSettings)
            }
            "com.android.vending.CHECK_LICENSE" => Ok(Self::ComAndroidVendingCheckLicense),
            "com.android.voicemail.permission.ADD_VOICEMAIL" => {
                Ok(Self::ComAndroidVoicemailPermissionAddVoicemail)
            }
            "com.android.voicemail.permission.READ_VOICEMAIL" => {
                Ok(Self::ComAndroidVoicemailPermissionReadVoicemail)
            }
            "com.android.voicemail.permission.READ_WRITE_ALL_VOICEMAIL" => {
                Ok(Self::ComAndroidVoicemailPermissionReadWriteAllVoicemail)
            }
            "com.android.voicemail.permission.WRITE_VOICEMAIL" => {
                Ok(Self::ComAndroidVoicemailPermissionWriteVoicemail)
            }
            "com.google.android.c2dm.permission.RECEIVE" => {
                Ok(Self::ComGoogleAndroidC2dmPermissionReceive)
            }
            "com.google.android.c2dm.permission.SEND" => {
                Ok(Self::ComGoogleAndroidC2dmPermissionSend)
            }
            "com.google.android.gms.permission.ACTIVITY_RECOGNITION" => {
                Ok(Self::ComGoogleAndroidGmsPermissionActivityRecognition)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuth)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.ALL_SERVICES" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAllServices)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.OTHER_SERVICES" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthOtherServices)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.YouTubeUser" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutubeuser)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.adsense" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAdsense)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.adwords" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAdwords)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.ah" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAh)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.android" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroid)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.androidsecure" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroidsecure)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.blogger" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthBlogger)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.cl" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthCl)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.cp" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthCp)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.dodgeball" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthDodgeball)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.doraemon" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthDoraemon)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.finance" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthFinance)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.gbase" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGbase)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.geowiki" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGeowiki)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.goanna_mobile" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGoannaMobile)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.grandcentral" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGrandcentral)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.groups2" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGroups2)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.health" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthHealth)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.ig" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthIg)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.jotspot" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthJotspot)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.knol" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthKnol)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.lh2" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthLh2)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.local" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthLocal)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.mail" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthMail)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.mobile" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthMobile)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.news" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthNews)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.notebook" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthNotebook)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.orkut" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthOrkut)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.panoramio" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthPanoramio)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.print" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthPrint)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.reader" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthReader)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.sierra" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierra)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.sierraqa" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierraqa)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.sierrasandbox" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierrasandbox)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.sitemaps" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSitemaps)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.speech" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeech)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.speechpersonalization" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeechpersonalization)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.talk" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthTalk)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.wifi" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthWifi)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.wise" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthWise)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.writely" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthWritely)
            }
            "com.google.android.googleapps.permission.GOOGLE_AUTH.youtube" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutube)
            }
            "com.google.android.gtalkservice.permission.GTALK_SERVICE" => {
                Ok(Self::ComGoogleAndroidGtalkservicePermissionGtalkService)
            }
            "com.google.android.gtalkservice.permission.SEND_HEARTBEAT" => {
                Ok(Self::ComGoogleAndroidGtalkservicePermissionSendHeartbeat)
            }
            "com.google.android.permission.BROADCAST_DATA_MESSAGE" => {
                Ok(Self::ComGoogleAndroidPermissionBroadcastDataMessage)
            }
            "com.google.android.providers.gsf.permission.READ_GSERVICES" => {
                Ok(Self::ComGoogleAndroidProvidersGsfPermissionReadGservices)
            }
            "com.google.android.providers.talk.permission.READ_ONLY" => {
                Ok(Self::ComGoogleAndroidProvidersTalkPermissionReadOnly)
            }
            "com.google.android.providers.talk.permission.WRITE_ONLY" => {
                Ok(Self::ComGoogleAndroidProvidersTalkPermissionWriteOnly)
            }
            "com.google.android.xmpp.permission.BROADCAST" => {
                Ok(Self::ComGoogleAndroidXmppPermissionBroadcast)
            }
            "com.google.android.xmpp.permission.SEND_RECEIVE" => {
                Ok(Self::ComGoogleAndroidXmppPermissionSendReceive)
            }
            "com.google.android.xmpp.permission.USE_XMPP_ENDPOINT" => {
                Ok(Self::ComGoogleAndroidXmppPermissionUseXmppEndpoint)
            }
            "com.google.android.xmpp.permission.XMPP_ENDPOINT_BROADCAST" => {
                Ok(Self::ComGoogleAndroidXmppPermissionXmppEndpointBroadcast)
            }
            _ => Err(ErrorKind::Parse),
        }
    }
}
