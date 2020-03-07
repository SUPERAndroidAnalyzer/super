//! Module implementing a checklist for the permissions.

use super::Permission;

#[derive(Debug, Default)]
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
    pub fn set_needs_permission(&mut self, p: Permission) {
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
