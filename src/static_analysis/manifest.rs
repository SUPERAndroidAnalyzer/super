use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use xml::reader::{EventReader, XmlEvent};
use xml::ParserConfig;
use colored::Colorize;

use {Error, Config, Result, Criticity, print_error, print_warning, print_vulnerability, get_line,
     get_code};
use results::Results;

const PARSER_CONFIG: ParserConfig = ParserConfig {
    trim_whitespace: true,
    whitespace_to_characters: false,
    cdata_to_characters: false,
    ignore_comments: true,
    coalesce_characters: true,
};


pub fn manifest_analysis(config: &Config, results: &mut Results) {
    if config.is_verbose() {
        println!("Loading the manifest file. For this, we first parse the document and then we'll \
                  analize it.")
    }

    let manifest = match Manifest::load(format!("{}/{}/AndroidManifest.xml",
                                                config.get_dist_folder(),
                                                config.get_app_id()),
                                        config.is_verbose()) {
        Ok(m) => {
            if config.is_verbose() {
                println!("{}", "The manifest was loaded successfully!".green());
                println!("");
            }
            m
        }
        Err(e) => {
            print_error(format!("There was an error when loading the manifest: {}", e),
                        config.is_verbose());
            if config.is_verbose() {
                println!("The rest of the analysis will continue, but there will be no analysis \
                          of the AndroidManifest.xml file.");
            }
            return;
        }
    };

    if manifest.get_package() != config.get_app_id() {
        print_warning(format!("Seems that the package in the AndroidManifest.xml is not the \
                               same as the application ID provided. Provided application id: \
                               {}, manifest package: {}",
                              config.get_app_id(),
                              manifest.get_package()),
                      config.is_verbose());

        if config.is_verbose() {
            println!("This does not mean that something is bad, but it's supposed to have the \
                      application in the format {{package}}.apk in the {} folder and use the \
                      package as the application ID for this auditor.",
                     config.get_downloads_folder());
        }
    }

    results.set_app_package(manifest.get_package());
    results.set_app_label(manifest.get_label());
    results.set_app_description(manifest.get_description());
    results.set_app_version(manifest.get_version_str());

    if manifest.is_debug() {
        let criticity = Criticity::Medium;
        let description = "The application is in debug mode. This is a vulnerability since \
                             the application will filter data to the Android OS to be \
                             debugged. This option should only be used while in development.";

        results.add_vulnerability(criticity,
                                  "Manifest Debug",
                                  description,
                                  "AndroidManifest.xml",
                                  None,
                                  None);
        if config.is_verbose() {
            print_vulnerability(description, criticity);
        }
    }

    if manifest.needs_large_heap() {
        let criticity = Criticity::Low;
        let description = "The application needs a large heap. This is not a vulnerability \
                             as such, but could be in devices with small heap. Review if the \
                             large heap is actually needed.";

        results.add_vulnerability(criticity,
                                  "Large heap",
                                  description,
                                  "AndroidManifest.xml",
                                  None,
                                  None);
        if config.is_verbose() {
            print_vulnerability(description, criticity);
        }
    }

    if manifest.get_permission_checklist().needs_permission(Permission::Internet) {
        let criticity = Criticity::Low;
        let description = "The application needs Internet access. This is not a \
                             vulnerability as such, but it needs additional security measures \
                             if it's being connected to the Internet. Check if the \
                             permission is actually needed.";

        let line = get_line(manifest.get_code(), Permission::Internet.as_str()).ok();
        let code = match line {
            Some(l) => Some(get_code(manifest.get_code(), l - 1)),
            None => None,
        };

        results.add_vulnerability(criticity,
                                  "Internet permission",
                                  description,
                                  "AndroidManifest.xml",
                                  line,
                                  code);

        if config.is_verbose() {
            print_vulnerability(description, criticity);
        }
    }

    if manifest.get_permission_checklist().needs_permission(Permission::WriteExternalStorage) {
        let criticity = Criticity::Medium;
        let description = "The application needs external storage access. This could be a \
                             security issue if those accesses are not controled.";

        let line = get_line(manifest.get_code(),
                            Permission::WriteExternalStorage.as_str())
                       .ok();

        let code = match line {
            Some(l) => Some(get_code(manifest.get_code(), l - 1)),
            None => None,
        };

        results.add_vulnerability(criticity,
                                  "External storage write permission",
                                  description,
                                  "AndroidManifest.xml",
                                  line,
                                  code);

        if config.is_verbose() {
            print_vulnerability(description, criticity);
        }
    }

    if config.is_verbose() {
        println!("");
        println!("{}", "The manifest was analized correctly!".green());
    } else if !config.is_quiet() {
        println!("Manifest analyzed.");
    }
}

struct Manifest {
    code: String,
    package: String,
    version_number: i32,
    version_str: String,
    label: String,
    description: String,
    has_code: bool,
    large_heap: bool,
    install_location: InstallLocation,
    permissions: PermissionChecklist,
    debug: bool,
}

impl Manifest {
    pub fn load<P: AsRef<Path>>(path: P, verbose: bool) -> Result<Manifest> {
        let mut file = try!(File::open(path));

        let mut manifest: Manifest = Default::default();

        let mut code = String::new();
        try!(file.read_to_string(&mut code));
        manifest.set_code(code.as_str());

        let bytes = code.into_bytes();
        let parser = EventReader::new_with_config(bytes.as_slice(), PARSER_CONFIG);

        for e in parser {
            match e {
                Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                    match name.local_name.as_str() {
                        "manifest" => {
                            for attr in attributes {
                                match attr.name.local_name.as_str() {
                                    "package" => manifest.set_package(attr.value.as_str()),
                                    "versionCode" => {
                                        let version_number: i32 = match attr.value.parse() {
                                            Ok(n) => n,
                                            Err(e) => {
                                                print_warning(format!("An error occurred when \
                                                                       parsing the version in \
                                                                       the manifest: {}.\nThe \
                                                                       process will continue, \
                                                                       though.",
                                                                      e),
                                                              verbose);
                                                break;
                                            }
                                        };
                                        manifest.set_version_number(version_number);
                                    }
                                    "versionName" => manifest.set_version_str(attr.value.as_str()),
                                    "installLocation" => {
                                        let location =
                                            match InstallLocation::from_str(attr.value
                                                                                .as_str()) {
                                                Ok(l) => l,
                                                Err(e) => {
                                                    print_warning(format!("An error occurred \
                                                                           when parsing the \
                                                                           installLocation \
                                                                           attribute in the \
                                                                           manifest: {}.\nThe \
                                                                           process will \
                                                                           continue, though.",
                                                                          e),
                                                                  verbose);
                                                    break;
                                                }
                                            };
                                        manifest.set_install_location(location)
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "application" => {
                            for attr in attributes {
                                match attr.name.local_name.as_str() {
                                    "debuggable" => {
                                        let debug = match attr.value.as_str().parse() {
                                            Ok(b) => b,
                                            Err(e) => {
                                                print_warning(format!("An error occurred \
                                                                       when parsing the \
                                                                       debuggable attribute in \
                                                                       the manifest: \
                                                                       {}.\nThe process \
                                                                       will continue, though.",
                                                                      e),
                                                              verbose);
                                                break;
                                            }
                                        };
                                        if debug {
                                            manifest.set_debug();
                                        }
                                    }
                                    "description" => manifest.set_description(attr.value.as_str()),
                                    "hasCode" => {
                                        let has_code = match attr.value.as_str().parse() {
                                            Ok(b) => b,
                                            Err(e) => {
                                                print_warning(format!("An error occurred \
                                                                        when parsing the \
                                                                    hasCode attribute in \
                                                                           the manifest: \
                                                                        {}.\nThe process \
                                                                    will continue, though.",
                                                                      e),
                                                              verbose);
                                                break;
                                            }
                                        };
                                        if has_code {
                                            manifest.set_has_code();
                                        }
                                    }
                                    "largeHeap" => {
                                        let large_heap = match attr.value.as_str().parse() {
                                            Ok(b) => b,
                                            Err(e) => {
                                                print_warning(format!("An error occurred \
                                                                        when parsing the \
                                                                  largeHeap attribute in \
                                                                          the manifest: \
                                                                        {}.\nThe process \
                                                                    will continue, though.",
                                                                      e),
                                                              verbose);
                                                break;
                                            }
                                        };
                                        if large_heap {
                                            manifest.set_large_heap();
                                        }
                                    }
                                    "label" => manifest.set_label(attr.value.as_str()),
                                    _ => {}
                                }
                            }
                        }
                        "provider" => {}
                        "uses-permission" => {
                            for attr in attributes {
                                match attr.name.local_name.as_str() {
                                    "name" => {
                                        let perm_str = &attr.value.as_str()[19..];
                                        let permission = match Permission::from_str(perm_str) {
                                            Ok(p) => p,
                                            Err(e) => {
                                                print_warning(format!("An error occurred when \
                                                                       parsing a permission in \
                                                                       the manifest: {}. \
                                                                       Manifest's permission: \
                                                                       {}.\nThe process will \
                                                                       continue, though.",
                                                                      attr.value.as_str(),
                                                                      e),
                                                              verbose);
                                                break;
                                            }
                                        };
                                        manifest.get_mut_permission_checklist()
                                                .set_needs_permission(permission);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                    // TODO
                }
                Ok(_) => {}
                Err(e) => {
                    print_warning(format!("An error occurred when parsing the \
                                           AndroidManifest.xml file: {}.\nThe process will \
                                           continue, though.",
                                          e),
                                  verbose);
                }
            }
        }

        Ok(manifest)
    }

    fn set_code(&mut self, code: &str) {
        self.code = String::from(code);
    }

    pub fn get_code(&self) -> &str {
        self.code.as_str()
    }

    pub fn get_package(&self) -> &str {
        self.package.as_str()
    }

    fn set_package(&mut self, package: &str) {
        self.package = String::from(package);
    }

    pub fn get_version_number(&self) -> i32 {
        self.version_number
    }

    fn set_version_number(&mut self, version_number: i32) {
        self.version_number = version_number;
    }

    pub fn get_version_str(&self) -> &str {
        self.version_str.as_str()
    }

    fn set_version_str(&mut self, version_str: &str) {
        self.version_str = String::from(version_str);
    }

    pub fn get_label(&self) -> &str {
        self.label.as_str()
    }

    fn set_label(&mut self, label: &str) {
        self.label = String::from(label);
    }

    pub fn get_description(&self) -> &str {
        self.description.as_str()
    }

    fn set_description(&mut self, description: &str) {
        self.description = String::from(description);
    }

    pub fn has_code(&self) -> bool {
        self.has_code
    }

    fn set_has_code(&mut self) {
        self.has_code = true;
    }

    pub fn needs_large_heap(&self) -> bool {
        self.large_heap
    }

    fn set_large_heap(&mut self) {
        self.large_heap = true;
    }

    pub fn get_install_location(&self) -> InstallLocation {
        self.install_location
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

    pub fn get_permission_checklist(&self) -> &PermissionChecklist {
        &self.permissions
    }

    fn get_mut_permission_checklist(&mut self) -> &mut PermissionChecklist {
        &mut self.permissions
    }
}

impl Default for Manifest {
    fn default() -> Manifest {
        Manifest {
            code: String::new(),
            package: String::new(),
            version_number: 0,
            version_str: String::new(),
            label: String::new(),
            description: String::new(),
            has_code: false,
            large_heap: false,
            install_location: InstallLocation::InternalOnly,
            permissions: Default::default(),
            debug: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum InstallLocation {
    InternalOnly,
    Auto,
    PreferExternal,
}

impl FromStr for InstallLocation {
    type Err = Error;
    fn from_str(s: &str) -> Result<InstallLocation> {
        match s {
            "internalOnly" => Ok(InstallLocation::InternalOnly),
            "auto" => Ok(InstallLocation::Auto),
            "preferExternal" => Ok(InstallLocation::PreferExternal),
            _ => Err(Error::ParseError),
        }
    }
}

struct PermissionChecklist {
    access_checkin_properties: bool,
    access_coarse_location: bool,
    access_fine_location: bool,
    access_location_extra_commands: bool,
    access_network_state: bool,
    access_notification_policy: bool,
    access_wifi_state: bool,
    account_manager: bool,
    add_voicemail: bool,
    battery_stats: bool,
    bind_accessibility_service: bool,
    bind_appwidget: bool,
    bind_carrier_messaging_service: bool,
    bind_carrier_services: bool,
    bind_chooser_target_service: bool,
    bind_device_admin: bool,
    bind_dream_service: bool,
    bind_incall_service: bool,
    bind_input_method: bool,
    bind_midi_device_service: bool,
    bind_nfc_service: bool,
    bind_notification_listener_service: bool,
    bind_print_service: bool,
    bind_remoteviews: bool,
    bind_telecom_connection_service: bool,
    bind_text_service: bool,
    bind_tv_input: bool,
    bind_voice_interaction: bool,
    bind_vpn_service: bool,
    bind_wallpaper: bool,
    bluetooth: bool,
    bluetooth_admin: bool,
    bluetooth_privileged: bool,
    body_sensors: bool,
    broadcast_package_removed: bool,
    broadcast_sms: bool,
    broadcast_sticky: bool,
    broadcast_wap_push: bool,
    call_phone: bool,
    call_privileged: bool,
    camera: bool,
    capture_audio_output: bool,
    capture_secure_video_output: bool,
    capture_video_output: bool,
    change_component_enabled_state: bool,
    change_configuration: bool,
    change_network_state: bool,
    change_wifi_multicast_state: bool,
    change_wifi_state: bool,
    clear_app_cache: bool,
    control_location_updates: bool,
    delete_cache_files: bool,
    delete_packages: bool,
    diagnostic: bool,
    disable_keyguard: bool,
    dump: bool,
    expand_status_bar: bool,
    factory_test: bool,
    flashlight: bool,
    get_accounts: bool,
    get_accounts_privileged: bool,
    get_package_size: bool,
    get_tasks: bool,
    global_search: bool,
    install_location_provider: bool,
    install_packages: bool,
    install_shortcut: bool,
    internet: bool,
    kill_background_processes: bool,
    location_hardware: bool,
    manage_documents: bool,
    master_clear: bool,
    media_content_control: bool,
    modify_audio_settings: bool,
    modify_phone_state: bool,
    mount_format_filesystems: bool,
    mount_unmount_filesystems: bool,
    nfc: bool,
    package_usage_stats: bool,
    persistent_activity: bool,
    process_outgoing_calls: bool,
    read_calendar: bool,
    read_call_log: bool,
    read_contacts: bool,
    read_external_storage: bool,
    read_frame_buffer: bool,
    read_input_state: bool,
    read_logs: bool,
    read_phone_state: bool,
    read_sms: bool,
    read_sync_settings: bool,
    read_sync_stats: bool,
    read_voicemail: bool,
    reboot: bool,
    receive_boot_completed: bool,
    receive_mms: bool,
    receive_sms: bool,
    receive_wap_push: bool,
    record_audio: bool,
    reorder_tasks: bool,
    request_ignore_battery_optimizations: bool,
    request_install_packages: bool,
    restart_packages: bool,
    send_respond_via_message: bool,
    send_sms: bool,
    set_alarm: bool,
    set_always_finish: bool,
    set_animation_scale: bool,
    set_debug_app: bool,
    set_preferred_applications: bool,
    set_process_limit: bool,
    set_time: bool,
    set_time_zone: bool,
    set_wallpaper: bool,
    set_wallpaper_hints: bool,
    signal_persistent_processes: bool,
    status_bar: bool,
    system_alert_window: bool,
    transmit_ir: bool,
    uninstall_shortcut: bool,
    update_device_stats: bool,
    use_fingerprint: bool,
    use_sip: bool,
    vibrate: bool,
    wake_lock: bool,
    write_apn_settings: bool,
    write_calendar: bool,
    write_call_log: bool,
    write_contacts: bool,
    write_external_storage: bool,
    write_gservices: bool,
    write_secure_settings: bool,
    write_settings: bool,
    write_sync_settings: bool,
    write_voicemail: bool,
}

impl PermissionChecklist {
    pub fn needs_permission(&self, p: Permission) -> bool {
        match p {
            Permission::AccessCheckinProperties => self.access_checkin_properties,
            Permission::AccessCoarseLocation => self.access_coarse_location,
            Permission::AccessFineLocation => self.access_fine_location,
            Permission::AccessLocationExtraCommands => self.access_location_extra_commands,
            Permission::AccessNetworkState => self.access_network_state,
            Permission::AccessNotificationPolicy => self.access_notification_policy,
            Permission::AccessWifiState => self.access_wifi_state,
            Permission::AccountManager => self.account_manager,
            Permission::AddVoicemail => self.add_voicemail,
            Permission::BatteryStats => self.battery_stats,
            Permission::BindAccessibilityService => self.bind_accessibility_service,
            Permission::BindAppwidget => self.bind_appwidget,
            Permission::BindCarrierMessagingService => self.bind_carrier_messaging_service,
            Permission::BindCarrierServices => self.bind_carrier_services,
            Permission::BindChooserTargetService => self.bind_chooser_target_service,
            Permission::BindDeviceAdmin => self.bind_device_admin,
            Permission::BindDreamService => self.bind_dream_service,
            Permission::BindIncallService => self.bind_incall_service,
            Permission::BindInputMethod => self.bind_input_method,
            Permission::BindMidiDeviceService => self.bind_midi_device_service,
            Permission::BindNfcService => self.bind_nfc_service,
            Permission::BindNotificationListenerService => self.bind_notification_listener_service,
            Permission::BindPrintService => self.bind_print_service,
            Permission::BindRemoteviews => self.bind_remoteviews,
            Permission::BindTelecomConnectionService => self.bind_telecom_connection_service,
            Permission::BindTextService => self.bind_text_service,
            Permission::BindTvInput => self.bind_tv_input,
            Permission::BindVoiceInteraction => self.bind_voice_interaction,
            Permission::BindVpnService => self.bind_vpn_service,
            Permission::BindWallpaper => self.bind_wallpaper,
            Permission::Bluetooth => self.bluetooth,
            Permission::BluetoothAdmin => self.bluetooth_admin,
            Permission::BluetoothPrivileged => self.bluetooth_privileged,
            Permission::BodySensors => self.body_sensors,
            Permission::BroadcastPackageRemoved => self.broadcast_package_removed,
            Permission::BroadcastSms => self.broadcast_sms,
            Permission::BroadcastSticky => self.broadcast_sticky,
            Permission::BroadcastWapPush => self.broadcast_wap_push,
            Permission::CallPhone => self.call_phone,
            Permission::CallPrivileged => self.call_privileged,
            Permission::Camera => self.camera,
            Permission::CaptureAudioOutput => self.capture_audio_output,
            Permission::CaptureSecureVideoOutput => self.capture_secure_video_output,
            Permission::CaptureVideoOutput => self.capture_video_output,
            Permission::ChangeComponentEnabledState => self.change_component_enabled_state,
            Permission::ChangeConfiguration => self.change_configuration,
            Permission::ChangeNetworkState => self.change_network_state,
            Permission::ChangeWifiMulticastState => self.change_wifi_multicast_state,
            Permission::ChangeWifiState => self.change_wifi_state,
            Permission::ClearAppCache => self.clear_app_cache,
            Permission::ControlLocationUpdates => self.control_location_updates,
            Permission::DeleteCacheFiles => self.delete_cache_files,
            Permission::DeletePackages => self.delete_packages,
            Permission::Diagnostic => self.diagnostic,
            Permission::DisableKeyguard => self.disable_keyguard,
            Permission::Dump => self.dump,
            Permission::ExpandStatusBar => self.expand_status_bar,
            Permission::FactoryTest => self.factory_test,
            Permission::Flashlight => self.flashlight,
            Permission::GetAccounts => self.get_accounts,
            Permission::GetAccountsPrivileged => self.get_accounts_privileged,
            Permission::GetPackageSize => self.get_package_size,
            Permission::GetTasks => self.get_tasks,
            Permission::GlobalSearch => self.global_search,
            Permission::InstallLocationProvider => self.install_location_provider,
            Permission::InstallPackages => self.install_packages,
            Permission::InstallShortcut => self.install_shortcut,
            Permission::Internet => self.internet,
            Permission::KillBackgroundProcesses => self.kill_background_processes,
            Permission::LocationHardware => self.location_hardware,
            Permission::ManageDocuments => self.manage_documents,
            Permission::MasterClear => self.master_clear,
            Permission::MediaContentControl => self.media_content_control,
            Permission::ModifyAudioSettings => self.modify_audio_settings,
            Permission::ModifyPhoneState => self.modify_phone_state,
            Permission::MountFormatFilesystems => self.mount_format_filesystems,
            Permission::MountUnmountFilesystems => self.mount_unmount_filesystems,
            Permission::Nfc => self.nfc,
            Permission::PackageUsageStats => self.package_usage_stats,
            Permission::PersistentActivity => self.persistent_activity,
            Permission::ProcessOutgoingCalls => self.process_outgoing_calls,
            Permission::ReadCalendar => self.read_calendar,
            Permission::ReadCallLog => self.read_call_log,
            Permission::ReadContacts => self.read_contacts,
            Permission::ReadExternalStorage => self.read_external_storage,
            Permission::ReadFrameBuffer => self.read_frame_buffer,
            Permission::ReadInputState => self.read_input_state,
            Permission::ReadLogs => self.read_logs,
            Permission::ReadPhoneState => self.read_phone_state,
            Permission::ReadSms => self.read_sms,
            Permission::ReadSyncSettings => self.read_sync_settings,
            Permission::ReadSyncStats => self.read_sync_stats,
            Permission::ReadVoicemail => self.read_voicemail,
            Permission::Reboot => self.reboot,
            Permission::ReceiveBootCompleted => self.receive_boot_completed,
            Permission::ReceiveMms => self.receive_mms,
            Permission::ReceiveSms => self.receive_sms,
            Permission::ReceiveWapPush => self.receive_wap_push,
            Permission::RecordAudio => self.record_audio,
            Permission::ReorderTasks => self.reorder_tasks,
            Permission::RequestIgnoreBatteryOptimizations => {
                self.request_ignore_battery_optimizations
            }
            Permission::RequestInstallPackages => self.request_install_packages,
            Permission::RestartPackages => self.restart_packages,
            Permission::SendRespondViaMessage => self.send_respond_via_message,
            Permission::SendSms => self.send_sms,
            Permission::SetAlarm => self.set_alarm,
            Permission::SetAlwaysFinish => self.set_always_finish,
            Permission::SetAnimationScale => self.set_animation_scale,
            Permission::SetDebugApp => self.set_debug_app,
            Permission::SetPreferredApplications => self.set_preferred_applications,
            Permission::SetProcessLimit => self.set_process_limit,
            Permission::SetTime => self.set_time,
            Permission::SetTimeZone => self.set_time_zone,
            Permission::SetWallpaper => self.set_wallpaper,
            Permission::SetWallpaperHints => self.set_wallpaper_hints,
            Permission::SignalPersistentProcesses => self.signal_persistent_processes,
            Permission::StatusBar => self.status_bar,
            Permission::SystemAlertWindow => self.system_alert_window,
            Permission::TransmitIr => self.transmit_ir,
            Permission::UninstallShortcut => self.uninstall_shortcut,
            Permission::UpdateDeviceStats => self.update_device_stats,
            Permission::UseFingerprint => self.use_fingerprint,
            Permission::UseSip => self.use_sip,
            Permission::Vibrate => self.vibrate,
            Permission::WakeLock => self.wake_lock,
            Permission::WriteApnSettings => self.write_apn_settings,
            Permission::WriteCalendar => self.write_calendar,
            Permission::WriteCallLog => self.write_call_log,
            Permission::WriteContacts => self.write_contacts,
            Permission::WriteExternalStorage => self.write_external_storage,
            Permission::WriteGservices => self.write_gservices,
            Permission::WriteSecureSettings => self.write_secure_settings,
            Permission::WriteSettings => self.write_settings,
            Permission::WriteSyncSettings => self.write_sync_settings,
            Permission::WriteVoicemail => self.write_voicemail,
        }
    }

    fn set_needs_permission(&mut self, p: Permission) {
        match p {
            Permission::AccessCheckinProperties => self.access_checkin_properties = true,
            Permission::AccessCoarseLocation => self.access_coarse_location = true,
            Permission::AccessFineLocation => self.access_fine_location = true,
            Permission::AccessLocationExtraCommands => self.access_location_extra_commands = true,
            Permission::AccessNetworkState => self.access_network_state = true,
            Permission::AccessNotificationPolicy => self.access_notification_policy = true,
            Permission::AccessWifiState => self.access_wifi_state = true,
            Permission::AccountManager => self.account_manager = true,
            Permission::AddVoicemail => self.add_voicemail = true,
            Permission::BatteryStats => self.battery_stats = true,
            Permission::BindAccessibilityService => self.bind_accessibility_service = true,
            Permission::BindAppwidget => self.bind_appwidget = true,
            Permission::BindCarrierMessagingService => self.bind_carrier_messaging_service = true,
            Permission::BindCarrierServices => self.bind_carrier_services = true,
            Permission::BindChooserTargetService => self.bind_chooser_target_service = true,
            Permission::BindDeviceAdmin => self.bind_device_admin = true,
            Permission::BindDreamService => self.bind_dream_service = true,
            Permission::BindIncallService => self.bind_incall_service = true,
            Permission::BindInputMethod => self.bind_input_method = true,
            Permission::BindMidiDeviceService => self.bind_midi_device_service = true,
            Permission::BindNfcService => self.bind_nfc_service = true,
            Permission::BindNotificationListenerService => {
                self.bind_notification_listener_service = true
            }
            Permission::BindPrintService => self.bind_print_service = true,
            Permission::BindRemoteviews => self.bind_remoteviews = true,
            Permission::BindTelecomConnectionService => self.bind_telecom_connection_service = true,
            Permission::BindTextService => self.bind_text_service = true,
            Permission::BindTvInput => self.bind_tv_input = true,
            Permission::BindVoiceInteraction => self.bind_voice_interaction = true,
            Permission::BindVpnService => self.bind_vpn_service = true,
            Permission::BindWallpaper => self.bind_wallpaper = true,
            Permission::Bluetooth => self.bluetooth = true,
            Permission::BluetoothAdmin => self.bluetooth_admin = true,
            Permission::BluetoothPrivileged => self.bluetooth_privileged = true,
            Permission::BodySensors => self.body_sensors = true,
            Permission::BroadcastPackageRemoved => self.broadcast_package_removed = true,
            Permission::BroadcastSms => self.broadcast_sms = true,
            Permission::BroadcastSticky => self.broadcast_sticky = true,
            Permission::BroadcastWapPush => self.broadcast_wap_push = true,
            Permission::CallPhone => self.call_phone = true,
            Permission::CallPrivileged => self.call_privileged = true,
            Permission::Camera => self.camera = true,
            Permission::CaptureAudioOutput => self.capture_audio_output = true,
            Permission::CaptureSecureVideoOutput => self.capture_secure_video_output = true,
            Permission::CaptureVideoOutput => self.capture_video_output = true,
            Permission::ChangeComponentEnabledState => self.change_component_enabled_state = true,
            Permission::ChangeConfiguration => self.change_configuration = true,
            Permission::ChangeNetworkState => self.change_network_state = true,
            Permission::ChangeWifiMulticastState => self.change_wifi_multicast_state = true,
            Permission::ChangeWifiState => self.change_wifi_state = true,
            Permission::ClearAppCache => self.clear_app_cache = true,
            Permission::ControlLocationUpdates => self.control_location_updates = true,
            Permission::DeleteCacheFiles => self.delete_cache_files = true,
            Permission::DeletePackages => self.delete_packages = true,
            Permission::Diagnostic => self.diagnostic = true,
            Permission::DisableKeyguard => self.disable_keyguard = true,
            Permission::Dump => self.dump = true,
            Permission::ExpandStatusBar => self.expand_status_bar = true,
            Permission::FactoryTest => self.factory_test = true,
            Permission::Flashlight => self.flashlight = true,
            Permission::GetAccounts => self.get_accounts = true,
            Permission::GetAccountsPrivileged => self.get_accounts_privileged = true,
            Permission::GetPackageSize => self.get_package_size = true,
            Permission::GetTasks => self.get_tasks = true,
            Permission::GlobalSearch => self.global_search = true,
            Permission::InstallLocationProvider => self.install_location_provider = true,
            Permission::InstallPackages => self.install_packages = true,
            Permission::InstallShortcut => self.install_shortcut = true,
            Permission::Internet => self.internet = true,
            Permission::KillBackgroundProcesses => self.kill_background_processes = true,
            Permission::LocationHardware => self.location_hardware = true,
            Permission::ManageDocuments => self.manage_documents = true,
            Permission::MasterClear => self.master_clear = true,
            Permission::MediaContentControl => self.media_content_control = true,
            Permission::ModifyAudioSettings => self.modify_audio_settings = true,
            Permission::ModifyPhoneState => self.modify_phone_state = true,
            Permission::MountFormatFilesystems => self.mount_format_filesystems = true,
            Permission::MountUnmountFilesystems => self.mount_unmount_filesystems = true,
            Permission::Nfc => self.nfc = true,
            Permission::PackageUsageStats => self.package_usage_stats = true,
            Permission::PersistentActivity => self.persistent_activity = true,
            Permission::ProcessOutgoingCalls => self.process_outgoing_calls = true,
            Permission::ReadCalendar => self.read_calendar = true,
            Permission::ReadCallLog => self.read_call_log = true,
            Permission::ReadContacts => self.read_contacts = true,
            Permission::ReadExternalStorage => self.read_external_storage = true,
            Permission::ReadFrameBuffer => self.read_frame_buffer = true,
            Permission::ReadInputState => self.read_input_state = true,
            Permission::ReadLogs => self.read_logs = true,
            Permission::ReadPhoneState => self.read_phone_state = true,
            Permission::ReadSms => self.read_sms = true,
            Permission::ReadSyncSettings => self.read_sync_settings = true,
            Permission::ReadSyncStats => self.read_sync_stats = true,
            Permission::ReadVoicemail => self.read_voicemail = true,
            Permission::Reboot => self.reboot = true,
            Permission::ReceiveBootCompleted => self.receive_boot_completed = true,
            Permission::ReceiveMms => self.receive_mms = true,
            Permission::ReceiveSms => self.receive_sms = true,
            Permission::ReceiveWapPush => self.receive_wap_push = true,
            Permission::RecordAudio => self.record_audio = true,
            Permission::ReorderTasks => self.reorder_tasks = true,
            Permission::RequestIgnoreBatteryOptimizations => {
                self.request_ignore_battery_optimizations = true
            }
            Permission::RequestInstallPackages => self.request_install_packages = true,
            Permission::RestartPackages => self.restart_packages = true,
            Permission::SendRespondViaMessage => self.send_respond_via_message = true,
            Permission::SendSms => self.send_sms = true,
            Permission::SetAlarm => self.set_alarm = true,
            Permission::SetAlwaysFinish => self.set_always_finish = true,
            Permission::SetAnimationScale => self.set_animation_scale = true,
            Permission::SetDebugApp => self.set_debug_app = true,
            Permission::SetPreferredApplications => self.set_preferred_applications = true,
            Permission::SetProcessLimit => self.set_process_limit = true,
            Permission::SetTime => self.set_time = true,
            Permission::SetTimeZone => self.set_time_zone = true,
            Permission::SetWallpaper => self.set_wallpaper = true,
            Permission::SetWallpaperHints => self.set_wallpaper_hints = true,
            Permission::SignalPersistentProcesses => self.signal_persistent_processes = true,
            Permission::StatusBar => self.status_bar = true,
            Permission::SystemAlertWindow => self.system_alert_window = true,
            Permission::TransmitIr => self.transmit_ir = true,
            Permission::UninstallShortcut => self.uninstall_shortcut = true,
            Permission::UpdateDeviceStats => self.update_device_stats = true,
            Permission::UseFingerprint => self.use_fingerprint = true,
            Permission::UseSip => self.use_sip = true,
            Permission::Vibrate => self.vibrate = true,
            Permission::WakeLock => self.wake_lock = true,
            Permission::WriteApnSettings => self.write_apn_settings = true,
            Permission::WriteCalendar => self.write_calendar = true,
            Permission::WriteCallLog => self.write_call_log = true,
            Permission::WriteContacts => self.write_contacts = true,
            Permission::WriteExternalStorage => self.write_external_storage = true,
            Permission::WriteGservices => self.write_gservices = true,
            Permission::WriteSecureSettings => self.write_secure_settings = true,
            Permission::WriteSettings => self.write_settings = true,
            Permission::WriteSyncSettings => self.write_sync_settings = true,
            Permission::WriteVoicemail => self.write_voicemail = true,
        }
    }
}

impl Default for PermissionChecklist {
    fn default() -> PermissionChecklist {
        PermissionChecklist {
            access_checkin_properties: false,
            access_coarse_location: false,
            access_fine_location: false,
            access_location_extra_commands: false,
            access_network_state: false,
            access_notification_policy: false,
            access_wifi_state: false,
            account_manager: false,
            add_voicemail: false,
            battery_stats: false,
            bind_accessibility_service: false,
            bind_appwidget: false,
            bind_carrier_messaging_service: false,
            bind_carrier_services: false,
            bind_chooser_target_service: false,
            bind_device_admin: false,
            bind_dream_service: false,
            bind_incall_service: false,
            bind_input_method: false,
            bind_midi_device_service: false,
            bind_nfc_service: false,
            bind_notification_listener_service: false,
            bind_print_service: false,
            bind_remoteviews: false,
            bind_telecom_connection_service: false,
            bind_text_service: false,
            bind_tv_input: false,
            bind_voice_interaction: false,
            bind_vpn_service: false,
            bind_wallpaper: false,
            bluetooth: false,
            bluetooth_admin: false,
            bluetooth_privileged: false,
            body_sensors: false,
            broadcast_package_removed: false,
            broadcast_sms: false,
            broadcast_sticky: false,
            broadcast_wap_push: false,
            call_phone: false,
            call_privileged: false,
            camera: false,
            capture_audio_output: false,
            capture_secure_video_output: false,
            capture_video_output: false,
            change_component_enabled_state: false,
            change_configuration: false,
            change_network_state: false,
            change_wifi_multicast_state: false,
            change_wifi_state: false,
            clear_app_cache: false,
            control_location_updates: false,
            delete_cache_files: false,
            delete_packages: false,
            diagnostic: false,
            disable_keyguard: false,
            dump: false,
            expand_status_bar: false,
            factory_test: false,
            flashlight: false,
            get_accounts: false,
            get_accounts_privileged: false,
            get_package_size: false,
            get_tasks: false,
            global_search: false,
            install_location_provider: false,
            install_packages: false,
            install_shortcut: false,
            internet: false,
            kill_background_processes: false,
            location_hardware: false,
            manage_documents: false,
            master_clear: false,
            media_content_control: false,
            modify_audio_settings: false,
            modify_phone_state: false,
            mount_format_filesystems: false,
            mount_unmount_filesystems: false,
            nfc: false,
            package_usage_stats: false,
            persistent_activity: false,
            process_outgoing_calls: false,
            read_calendar: false,
            read_call_log: false,
            read_contacts: false,
            read_external_storage: false,
            read_frame_buffer: false,
            read_input_state: false,
            read_logs: false,
            read_phone_state: false,
            read_sms: false,
            read_sync_settings: false,
            read_sync_stats: false,
            read_voicemail: false,
            reboot: false,
            receive_boot_completed: false,
            receive_mms: false,
            receive_sms: false,
            receive_wap_push: false,
            record_audio: false,
            reorder_tasks: false,
            request_ignore_battery_optimizations: false,
            request_install_packages: false,
            restart_packages: false,
            send_respond_via_message: false,
            send_sms: false,
            set_alarm: false,
            set_always_finish: false,
            set_animation_scale: false,
            set_debug_app: false,
            set_preferred_applications: false,
            set_process_limit: false,
            set_time: false,
            set_time_zone: false,
            set_wallpaper: false,
            set_wallpaper_hints: false,
            signal_persistent_processes: false,
            status_bar: false,
            system_alert_window: false,
            transmit_ir: false,
            uninstall_shortcut: false,
            update_device_stats: false,
            use_fingerprint: false,
            use_sip: false,
            vibrate: false,
            wake_lock: false,
            write_apn_settings: false,
            write_calendar: false,
            write_call_log: false,
            write_contacts: false,
            write_external_storage: false,
            write_gservices: false,
            write_secure_settings: false,
            write_settings: false,
            write_sync_settings: false,
            write_voicemail: false,
        }
    }
}

enum Permission {
    AccessCheckinProperties,
    AccessCoarseLocation,
    AccessFineLocation,
    AccessLocationExtraCommands,
    AccessNetworkState,
    AccessNotificationPolicy,
    AccessWifiState,
    AccountManager,
    AddVoicemail,
    BatteryStats,
    BindAccessibilityService,
    BindAppwidget,
    BindCarrierMessagingService,
    BindCarrierServices,
    BindChooserTargetService,
    BindDeviceAdmin,
    BindDreamService,
    BindIncallService,
    BindInputMethod,
    BindMidiDeviceService,
    BindNfcService,
    BindNotificationListenerService,
    BindPrintService,
    BindRemoteviews,
    BindTelecomConnectionService,
    BindTextService,
    BindTvInput,
    BindVoiceInteraction,
    BindVpnService,
    BindWallpaper,
    Bluetooth,
    BluetoothAdmin,
    BluetoothPrivileged,
    BodySensors,
    BroadcastPackageRemoved,
    BroadcastSms,
    BroadcastSticky,
    BroadcastWapPush,
    CallPhone,
    CallPrivileged,
    Camera,
    CaptureAudioOutput,
    CaptureSecureVideoOutput,
    CaptureVideoOutput,
    ChangeComponentEnabledState,
    ChangeConfiguration,
    ChangeNetworkState,
    ChangeWifiMulticastState,
    ChangeWifiState,
    ClearAppCache,
    ControlLocationUpdates,
    DeleteCacheFiles,
    DeletePackages,
    Diagnostic,
    DisableKeyguard,
    Dump,
    ExpandStatusBar,
    FactoryTest,
    Flashlight,
    GetAccounts,
    GetAccountsPrivileged,
    GetPackageSize,
    GetTasks,
    GlobalSearch,
    InstallLocationProvider,
    InstallPackages,
    InstallShortcut,
    Internet,
    KillBackgroundProcesses,
    LocationHardware,
    ManageDocuments,
    MasterClear,
    MediaContentControl,
    ModifyAudioSettings,
    ModifyPhoneState,
    MountFormatFilesystems,
    MountUnmountFilesystems,
    Nfc,
    PackageUsageStats,
    PersistentActivity,
    ProcessOutgoingCalls,
    ReadCalendar,
    ReadCallLog,
    ReadContacts,
    ReadExternalStorage,
    ReadFrameBuffer,
    ReadInputState,
    ReadLogs,
    ReadPhoneState,
    ReadSms,
    ReadSyncSettings,
    ReadSyncStats,
    ReadVoicemail,
    Reboot,
    ReceiveBootCompleted,
    ReceiveMms,
    ReceiveSms,
    ReceiveWapPush,
    RecordAudio,
    ReorderTasks,
    RequestIgnoreBatteryOptimizations,
    RequestInstallPackages,
    RestartPackages,
    SendRespondViaMessage,
    SendSms,
    SetAlarm,
    SetAlwaysFinish,
    SetAnimationScale,
    SetDebugApp,
    SetPreferredApplications,
    SetProcessLimit,
    SetTime,
    SetTimeZone,
    SetWallpaper,
    SetWallpaperHints,
    SignalPersistentProcesses,
    StatusBar,
    SystemAlertWindow,
    TransmitIr,
    UninstallShortcut,
    UpdateDeviceStats,
    UseFingerprint,
    UseSip,
    Vibrate,
    WakeLock,
    WriteApnSettings,
    WriteCalendar,
    WriteCallLog,
    WriteContacts,
    WriteExternalStorage,
    WriteGservices,
    WriteSecureSettings,
    WriteSettings,
    WriteSyncSettings,
    WriteVoicemail,
}

impl Permission {
    pub fn as_str(&self) -> &str {
        match *self {
            Permission::AccessCheckinProperties => "ACCESS_CHECKIN_PROPERTIES",
            Permission::AccessCoarseLocation => "ACCESS_COARSE_LOCATION",
            Permission::AccessFineLocation => "ACCESS_FINE_LOCATION",
            Permission::AccessLocationExtraCommands => "ACCESS_LOCATION_EXTRA_COMMANDS",
            Permission::AccessNetworkState => "ACCESS_NETWORK_STATE",
            Permission::AccessNotificationPolicy => "ACCESS_NOTIFICATION_POLICY",
            Permission::AccessWifiState => "ACCESS_WIFI_STATE",
            Permission::AccountManager => "ACCOUNT_MANAGER",
            Permission::AddVoicemail => "ADD_VOICEMAIL",
            Permission::BatteryStats => "BATTERY_STATS",
            Permission::BindAccessibilityService => "BIND_ACCESSIBILITY_SERVICE",
            Permission::BindAppwidget => "BIND_APPWIDGET",
            Permission::BindCarrierMessagingService => "BIND_CARRIER_MESSAGING_SERVICE",
            Permission::BindCarrierServices => "BIND_CARRIER_SERVICES",
            Permission::BindChooserTargetService => "BIND_CHOOSER_TARGET_SERVICE",
            Permission::BindDeviceAdmin => "BIND_DEVICE_ADMIN",
            Permission::BindDreamService => "BIND_DREAM_SERVICE",
            Permission::BindIncallService => "BIND_INCALL_SERVICE",
            Permission::BindInputMethod => "BIND_INPUT_METHOD",
            Permission::BindMidiDeviceService => "BIND_MIDI_DEVICE_SERVICE",
            Permission::BindNfcService => "BIND_NFC_SERVICE",
            Permission::BindNotificationListenerService => "BIND_NOTIFICATION_LISTENER_SERVICE",
            Permission::BindPrintService => "BIND_PRINT_SERVICE",
            Permission::BindRemoteviews => "BIND_REMOTEVIEWS",
            Permission::BindTelecomConnectionService => "BIND_TELECOM_CONNECTION_SERVICE",
            Permission::BindTextService => "BIND_TEXT_SERVICE",
            Permission::BindTvInput => "BIND_TV_INPUT",
            Permission::BindVoiceInteraction => "BIND_VOICE_INTERACTION",
            Permission::BindVpnService => "BIND_VPN_SERVICE",
            Permission::BindWallpaper => "BIND_WALLPAPER",
            Permission::Bluetooth => "BLUETOOTH",
            Permission::BluetoothAdmin => "BLUETOOTH_ADMIN",
            Permission::BluetoothPrivileged => "BLUETOOTH_PRIVILEGED",
            Permission::BodySensors => "BODY_SENSORS",
            Permission::BroadcastPackageRemoved => "BROADCAST_PACKAGE_REMOVED",
            Permission::BroadcastSms => "BROADCAST_SMS",
            Permission::BroadcastSticky => "BROADCAST_STICKY",
            Permission::BroadcastWapPush => "BROADCAST_WAP_PUSH",
            Permission::CallPhone => "CALL_PHONE",
            Permission::CallPrivileged => "CALL_PRIVILEGED",
            Permission::Camera => "CAMERA",
            Permission::CaptureAudioOutput => "CAPTURE_AUDIO_OUTPUT",
            Permission::CaptureSecureVideoOutput => "CAPTURE_SECURE_VIDEO_OUTPUT",
            Permission::CaptureVideoOutput => "CAPTURE_VIDEO_OUTPUT",
            Permission::ChangeComponentEnabledState => "CHANGE_COMPONENT_ENABLED_STATE",
            Permission::ChangeConfiguration => "CHANGE_CONFIGURATION",
            Permission::ChangeNetworkState => "CHANGE_NETWORK_STATE",
            Permission::ChangeWifiMulticastState => "CHANGE_WIFI_MULTICAST_STATE",
            Permission::ChangeWifiState => "CHANGE_WIFI_STATE",
            Permission::ClearAppCache => "CLEAR_APP_CACHE",
            Permission::ControlLocationUpdates => "CONTROL_LOCATION_UPDATES",
            Permission::DeleteCacheFiles => "DELETE_CACHE_FILES",
            Permission::DeletePackages => "DELETE_PACKAGES",
            Permission::Diagnostic => "DIAGNOSTIC",
            Permission::DisableKeyguard => "DISABLE_KEYGUARD",
            Permission::Dump => "DUMP",
            Permission::ExpandStatusBar => "EXPAND_STATUS_BAR",
            Permission::FactoryTest => "FACTORY_TEST",
            Permission::Flashlight => "FLASHLIGHT",
            Permission::GetAccounts => "GET_ACCOUNTS",
            Permission::GetAccountsPrivileged => "GET_ACCOUNTS_PRIVILEGED",
            Permission::GetPackageSize => "GET_PACKAGE_SIZE",
            Permission::GetTasks => "GET_TASKS",
            Permission::GlobalSearch => "GLOBAL_SEARCH",
            Permission::InstallLocationProvider => "INSTALL_LOCATION_PROVIDER",
            Permission::InstallPackages => "INSTALL_PACKAGES",
            Permission::InstallShortcut => "INSTALL_SHORTCUT",
            Permission::Internet => "INTERNET",
            Permission::KillBackgroundProcesses => "KILL_BACKGROUND_PROCESSES",
            Permission::LocationHardware => "LOCATION_HARDWARE",
            Permission::ManageDocuments => "MANAGE_DOCUMENTS",
            Permission::MasterClear => "MASTER_CLEAR",
            Permission::MediaContentControl => "MEDIA_CONTENT_CONTROL",
            Permission::ModifyAudioSettings => "MODIFY_AUDIO_SETTINGS",
            Permission::ModifyPhoneState => "MODIFY_PHONE_STATE",
            Permission::MountFormatFilesystems => "MOUNT_FORMAT_FILESYSTEMS",
            Permission::MountUnmountFilesystems => "MOUNT_UNMOUNT_FILESYSTEMS",
            Permission::Nfc => "NFC",
            Permission::PackageUsageStats => "PACKAGE_USAGE_STATS",
            Permission::PersistentActivity => "PERSISTENT_ACTIVITY",
            Permission::ProcessOutgoingCalls => "PROCESS_OUTGOING_CALLS",
            Permission::ReadCalendar => "READ_CALENDAR",
            Permission::ReadCallLog => "READ_CALL_LOG",
            Permission::ReadContacts => "READ_CONTACTS",
            Permission::ReadExternalStorage => "READ_EXTERNAL_STORAGE",
            Permission::ReadFrameBuffer => "READ_FRAME_BUFFER",
            Permission::ReadInputState => "READ_INPUT_STATE",
            Permission::ReadLogs => "READ_LOGS",
            Permission::ReadPhoneState => "READ_PHONE_STATE",
            Permission::ReadSms => "READ_SMS",
            Permission::ReadSyncSettings => "READ_SYNC_SETTINGS",
            Permission::ReadSyncStats => "READ_SYNC_STATS",
            Permission::ReadVoicemail => "READ_VOICEMAIL",
            Permission::Reboot => "REBOOT",
            Permission::ReceiveBootCompleted => "RECEIVE_BOOT_COMPLETED",
            Permission::ReceiveMms => "RECEIVE_MMS",
            Permission::ReceiveSms => "RECEIVE_SMS",
            Permission::ReceiveWapPush => "RECEIVE_WAP_PUSH",
            Permission::RecordAudio => "RECORD_AUDIO",
            Permission::ReorderTasks => "REORDER_TASKS",
            Permission::RequestIgnoreBatteryOptimizations => "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            Permission::RequestInstallPackages => "REQUEST_INSTALL_PACKAGES",
            Permission::RestartPackages => "RESTART_PACKAGES",
            Permission::SendRespondViaMessage => "SEND_RESPOND_VIA_MESSAGE",
            Permission::SendSms => "SEND_SMS",
            Permission::SetAlarm => "SET_ALARM",
            Permission::SetAlwaysFinish => "SET_ALWAYS_FINISH",
            Permission::SetAnimationScale => "SET_ANIMATION_SCALE",
            Permission::SetDebugApp => "SET_DEBUG_APP",
            Permission::SetPreferredApplications => "SET_PREFERRED_APPLICATIONS",
            Permission::SetProcessLimit => "SET_PROCESS_LIMIT",
            Permission::SetTime => "SET_TIME",
            Permission::SetTimeZone => "SET_TIME_ZONE",
            Permission::SetWallpaper => "SET_WALLPAPER",
            Permission::SetWallpaperHints => "SET_WALLPAPER_HINTS",
            Permission::SignalPersistentProcesses => "SIGNAL_PERSISTENT_PROCESSES",
            Permission::StatusBar => "STATUS_BAR",
            Permission::SystemAlertWindow => "SYSTEM_ALERT_WINDOW",
            Permission::TransmitIr => "TRANSMIT_IR",
            Permission::UninstallShortcut => "UNINSTALL_SHORTCUT",
            Permission::UpdateDeviceStats => "UPDATE_DEVICE_STATS",
            Permission::UseFingerprint => "USE_FINGERPRINT",
            Permission::UseSip => "USE_SIP",
            Permission::Vibrate => "VIBRATE",
            Permission::WakeLock => "WAKE_LOCK",
            Permission::WriteApnSettings => "WRITE_APN_SETTINGS",
            Permission::WriteCalendar => "WRITE_CALENDAR",
            Permission::WriteCallLog => "WRITE_CALL_LOG",
            Permission::WriteContacts => "WRITE_CONTACTS",
            Permission::WriteExternalStorage => "WRITE_EXTERNAL_STORAGE",
            Permission::WriteGservices => "WRITE_GSERVICES",
            Permission::WriteSecureSettings => "WRITE_SECURE_SETTINGS",
            Permission::WriteSettings => "WRITE_SETTINGS",
            Permission::WriteSyncSettings => "WRITE_SYNC_SETTINGS",
            Permission::WriteVoicemail => "WRITE_VOICEMAIL",
        }
    }
}

impl FromStr for Permission {
    type Err = Error;
    fn from_str(s: &str) -> Result<Permission> {
        match s {
            "ACCESS_CHECKIN_PROPERTIES" => Ok(Permission::AccessCheckinProperties),
            "ACCESS_COARSE_LOCATION" => Ok(Permission::AccessCoarseLocation),
            "ACCESS_FINE_LOCATION" => Ok(Permission::AccessFineLocation),
            "ACCESS_LOCATION_EXTRA_COMMANDS" => Ok(Permission::AccessLocationExtraCommands),
            "ACCESS_NETWORK_STATE" => Ok(Permission::AccessNetworkState),
            "ACCESS_NOTIFICATION_POLICY" => Ok(Permission::AccessNotificationPolicy),
            "ACCESS_WIFI_STATE" => Ok(Permission::AccessWifiState),
            "ACCOUNT_MANAGER" => Ok(Permission::AccountManager),
            "ADD_VOICEMAIL" => Ok(Permission::AddVoicemail),
            "BATTERY_STATS" => Ok(Permission::BatteryStats),
            "BIND_ACCESSIBILITY_SERVICE" => Ok(Permission::BindAccessibilityService),
            "BIND_APPWIDGET" => Ok(Permission::BindAppwidget),
            "BIND_CARRIER_MESSAGING_SERVICE" => Ok(Permission::BindCarrierMessagingService),
            "BIND_CARRIER_SERVICES" => Ok(Permission::BindCarrierServices),
            "BIND_CHOOSER_TARGET_SERVICE" => Ok(Permission::BindChooserTargetService),
            "BIND_DEVICE_ADMIN" => Ok(Permission::BindDeviceAdmin),
            "BIND_DREAM_SERVICE" => Ok(Permission::BindDreamService),
            "BIND_INCALL_SERVICE" => Ok(Permission::BindIncallService),
            "BIND_INPUT_METHOD" => Ok(Permission::BindInputMethod),
            "BIND_MIDI_DEVICE_SERVICE" => Ok(Permission::BindMidiDeviceService),
            "BIND_NFC_SERVICE" => Ok(Permission::BindNfcService),
            "BIND_NOTIFICATION_LISTENER_SERVICE" => Ok(Permission::BindNotificationListenerService),
            "BIND_PRINT_SERVICE" => Ok(Permission::BindPrintService),
            "BIND_REMOTEVIEWS" => Ok(Permission::BindRemoteviews),
            "BIND_TELECOM_CONNECTION_SERVICE" => Ok(Permission::BindTelecomConnectionService),
            "BIND_TEXT_SERVICE" => Ok(Permission::BindTextService),
            "BIND_TV_INPUT" => Ok(Permission::BindTvInput),
            "BIND_VOICE_INTERACTION" => Ok(Permission::BindVoiceInteraction),
            "BIND_VPN_SERVICE" => Ok(Permission::BindVpnService),
            "BIND_WALLPAPER" => Ok(Permission::BindWallpaper),
            "BLUETOOTH" => Ok(Permission::Bluetooth),
            "BLUETOOTH_ADMIN" => Ok(Permission::BluetoothAdmin),
            "BLUETOOTH_PRIVILEGED" => Ok(Permission::BluetoothPrivileged),
            "BODY_SENSORS" => Ok(Permission::BodySensors),
            "BROADCAST_PACKAGE_REMOVED" => Ok(Permission::BroadcastPackageRemoved),
            "BROADCAST_SMS" => Ok(Permission::BroadcastSms),
            "BROADCAST_STICKY" => Ok(Permission::BroadcastSticky),
            "BROADCAST_WAP_PUSH" => Ok(Permission::BroadcastWapPush),
            "CALL_PHONE" => Ok(Permission::CallPhone),
            "CALL_PRIVILEGED" => Ok(Permission::CallPrivileged),
            "CAMERA" => Ok(Permission::Camera),
            "CAPTURE_AUDIO_OUTPUT" => Ok(Permission::CaptureAudioOutput),
            "CAPTURE_SECURE_VIDEO_OUTPUT" => Ok(Permission::CaptureSecureVideoOutput),
            "CAPTURE_VIDEO_OUTPUT" => Ok(Permission::CaptureVideoOutput),
            "CHANGE_COMPONENT_ENABLED_STATE" => Ok(Permission::ChangeComponentEnabledState),
            "CHANGE_CONFIGURATION" => Ok(Permission::ChangeConfiguration),
            "CHANGE_NETWORK_STATE" => Ok(Permission::ChangeNetworkState),
            "CHANGE_WIFI_MULTICAST_STATE" => Ok(Permission::ChangeWifiMulticastState),
            "CHANGE_WIFI_STATE" => Ok(Permission::ChangeWifiState),
            "CLEAR_APP_CACHE" => Ok(Permission::ClearAppCache),
            "CONTROL_LOCATION_UPDATES" => Ok(Permission::ControlLocationUpdates),
            "DELETE_CACHE_FILES" => Ok(Permission::DeleteCacheFiles),
            "DELETE_PACKAGES" => Ok(Permission::DeletePackages),
            "DIAGNOSTIC" => Ok(Permission::Diagnostic),
            "DISABLE_KEYGUARD" => Ok(Permission::DisableKeyguard),
            "DUMP" => Ok(Permission::Dump),
            "EXPAND_STATUS_BAR" => Ok(Permission::ExpandStatusBar),
            "FACTORY_TEST" => Ok(Permission::FactoryTest),
            "FLASHLIGHT" => Ok(Permission::Flashlight),
            "GET_ACCOUNTS" => Ok(Permission::GetAccounts),
            "GET_ACCOUNTS_PRIVILEGED" => Ok(Permission::GetAccountsPrivileged),
            "GET_PACKAGE_SIZE" => Ok(Permission::GetPackageSize),
            "GET_TASKS" => Ok(Permission::GetTasks),
            "GLOBAL_SEARCH" => Ok(Permission::GlobalSearch),
            "INSTALL_LOCATION_PROVIDER" => Ok(Permission::InstallLocationProvider),
            "INSTALL_PACKAGES" => Ok(Permission::InstallPackages),
            "INSTALL_SHORTCUT" => Ok(Permission::InstallShortcut),
            "INTERNET" => Ok(Permission::Internet),
            "KILL_BACKGROUND_PROCESSES" => Ok(Permission::KillBackgroundProcesses),
            "LOCATION_HARDWARE" => Ok(Permission::LocationHardware),
            "MANAGE_DOCUMENTS" => Ok(Permission::ManageDocuments),
            "MASTER_CLEAR" => Ok(Permission::MasterClear),
            "MEDIA_CONTENT_CONTROL" => Ok(Permission::MediaContentControl),
            "MODIFY_AUDIO_SETTINGS" => Ok(Permission::ModifyAudioSettings),
            "MODIFY_PHONE_STATE" => Ok(Permission::ModifyPhoneState),
            "MOUNT_FORMAT_FILESYSTEMS" => Ok(Permission::MountFormatFilesystems),
            "MOUNT_UNMOUNT_FILESYSTEMS" => Ok(Permission::MountUnmountFilesystems),
            "NFC" => Ok(Permission::Nfc),
            "PACKAGE_USAGE_STATS" => Ok(Permission::PackageUsageStats),
            "PERSISTENT_ACTIVITY" => Ok(Permission::PersistentActivity),
            "PROCESS_OUTGOING_CALLS" => Ok(Permission::ProcessOutgoingCalls),
            "READ_CALENDAR" => Ok(Permission::ReadCalendar),
            "READ_CALL_LOG" => Ok(Permission::ReadCallLog),
            "READ_CONTACTS" => Ok(Permission::ReadContacts),
            "READ_EXTERNAL_STORAGE" => Ok(Permission::ReadExternalStorage),
            "READ_FRAME_BUFFER" => Ok(Permission::ReadFrameBuffer),
            "READ_INPUT_STATE" => Ok(Permission::ReadInputState),
            "READ_LOGS" => Ok(Permission::ReadLogs),
            "READ_PHONE_STATE" => Ok(Permission::ReadPhoneState),
            "READ_SMS" => Ok(Permission::ReadSms),
            "READ_SYNC_SETTINGS" => Ok(Permission::ReadSyncSettings),
            "READ_SYNC_STATS" => Ok(Permission::ReadSyncStats),
            "READ_VOICEMAIL" => Ok(Permission::ReadVoicemail),
            "REBOOT" => Ok(Permission::Reboot),
            "RECEIVE_BOOT_COMPLETED" => Ok(Permission::ReceiveBootCompleted),
            "RECEIVE_MMS" => Ok(Permission::ReceiveMms),
            "RECEIVE_SMS" => Ok(Permission::ReceiveSms),
            "RECEIVE_WAP_PUSH" => Ok(Permission::ReceiveWapPush),
            "RECORD_AUDIO" => Ok(Permission::RecordAudio),
            "REORDER_TASKS" => Ok(Permission::ReorderTasks),
            "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" => {
                Ok(Permission::RequestIgnoreBatteryOptimizations)
            }
            "REQUEST_INSTALL_PACKAGES" => Ok(Permission::RequestInstallPackages),
            "RESTART_PACKAGES" => Ok(Permission::RestartPackages),
            "SEND_RESPOND_VIA_MESSAGE" => Ok(Permission::SendRespondViaMessage),
            "SEND_SMS" => Ok(Permission::SendSms),
            "SET_ALARM" => Ok(Permission::SetAlarm),
            "SET_ALWAYS_FINISH" => Ok(Permission::SetAlwaysFinish),
            "SET_ANIMATION_SCALE" => Ok(Permission::SetAnimationScale),
            "SET_DEBUG_APP" => Ok(Permission::SetDebugApp),
            "SET_PREFERRED_APPLICATIONS" => Ok(Permission::SetPreferredApplications),
            "SET_PROCESS_LIMIT" => Ok(Permission::SetProcessLimit),
            "SET_TIME" => Ok(Permission::SetTime),
            "SET_TIME_ZONE" => Ok(Permission::SetTimeZone),
            "SET_WALLPAPER" => Ok(Permission::SetWallpaper),
            "SET_WALLPAPER_HINTS" => Ok(Permission::SetWallpaperHints),
            "SIGNAL_PERSISTENT_PROCESSES" => Ok(Permission::SignalPersistentProcesses),
            "STATUS_BAR" => Ok(Permission::StatusBar),
            "SYSTEM_ALERT_WINDOW" => Ok(Permission::SystemAlertWindow),
            "TRANSMIT_IR" => Ok(Permission::TransmitIr),
            "UNINSTALL_SHORTCUT" => Ok(Permission::UninstallShortcut),
            "UPDATE_DEVICE_STATS" => Ok(Permission::UpdateDeviceStats),
            "USE_FINGERPRINT" => Ok(Permission::UseFingerprint),
            "USE_SIP" => Ok(Permission::UseSip),
            "VIBRATE" => Ok(Permission::Vibrate),
            "WAKE_LOCK" => Ok(Permission::WakeLock),
            "WRITE_APN_SETTINGS" => Ok(Permission::WriteApnSettings),
            "WRITE_CALENDAR" => Ok(Permission::WriteCalendar),
            "WRITE_CALL_LOG" => Ok(Permission::WriteCallLog),
            "WRITE_CONTACTS" => Ok(Permission::WriteContacts),
            "WRITE_EXTERNAL_STORAGE" => Ok(Permission::WriteExternalStorage),
            "WRITE_GSERVICES" => Ok(Permission::WriteGservices),
            "WRITE_SECURE_SETTINGS" => Ok(Permission::WriteSecureSettings),
            "WRITE_SETTINGS" => Ok(Permission::WriteSettings),
            "WRITE_SYNC_SETTINGS" => Ok(Permission::WriteSyncSettings),
            "WRITE_VOICEMAIL" => Ok(Permission::WriteVoicemail),
            _ => Err(Error::ParseError),
        }
    }
}
