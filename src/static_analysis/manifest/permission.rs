//! Permission module.

use anyhow::{bail, Error};
use serde::{self, Deserialize, Deserializer};
use std::{
    convert::TryFrom,
    str::{self, FromStr},
};

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
        use serde::de::Error;

        let result_str: String = serde::Deserialize::deserialize(de)?;

        Self::try_from(result_str.as_bytes()).map_err(D::Error::custom)
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

impl TryFrom<&[u8]> for Permission {
    type Error = Error;

    #[allow(clippy::too_many_lines)]
    fn try_from(s: &[u8]) -> Result<Self, Error> {
        match s {
            b"android.permission.ACCESS_ALL_EXTERNAL_STORAGE" => {
                Ok(Self::AndroidPermissionAccessAllExternalStorage)
            }
            b"android.permission.ACCESS_CHECKIN_PROPERTIES" => {
                Ok(Self::AndroidPermissionAccessCheckinProperties)
            }
            b"android.permission.ACCESS_COARSE_LOCATION" => {
                Ok(Self::AndroidPermissionAccessCoarseLocation)
            }
            b"android.permission.ACCESS_FINE_LOCATION" => {
                Ok(Self::AndroidPermissionAccessFineLocation)
            }
            b"android.permission.ACCESS_LOCATION_EXTRA_COMMANDS" => {
                Ok(Self::AndroidPermissionAccessLocationExtraCommands)
            }
            b"android.permission.ACCESS_MOCK_LOCATION" => {
                Ok(Self::AndroidPermissionAccessMockLocation)
            }
            b"android.permission.ACCESS_MTP" => Ok(Self::AndroidPermissionAccessMtp),
            b"android.permission.ACCESS_NETWORK_STATE" => {
                Ok(Self::AndroidPermissionAccessNetworkState)
            }
            b"android.permission.ACCESS_NOTIFICATION_POLICY" => {
                Ok(Self::AndroidPermissionAccessNotificationPolicy)
            }
            b"android.permission.ACCESS_WIMAX_STATE" => Ok(Self::AndroidPermissionAccessWimaxState),
            b"android.permission.ACCESS_WIFI_STATE" => Ok(Self::AndroidPermissionAccessWifiState),
            b"android.permission.ACCOUNT_MANAGER" => Ok(Self::AndroidPermissionAccountManager),
            b"android.permission.ASEC_ACCESS" => Ok(Self::AndroidPermissionAsecAccess),
            b"android.permission.ASEC_CREATE" => Ok(Self::AndroidPermissionAsecCreate),
            b"android.permission.ASEC_DESTROY" => Ok(Self::AndroidPermissionAsecDestroy),
            b"android.permission.ASEC_MOUNT_UNMOUNT" => Ok(Self::AndroidPermissionAsecMountUnmount),
            b"android.permission.ASEC_RENAME" => Ok(Self::AndroidPermissionAsecRename),
            b"android.permission.AUTHENTICATE_ACCOUNTS" => {
                Ok(Self::AndroidPermissionAuthenticateAccounts)
            }
            b"android.permission.BATTERY_STATS" => Ok(Self::AndroidPermissionBatteryStats),
            b"android.permission.BIND_ACCESSIBILITY_SERVICE" => {
                Ok(Self::AndroidPermissionBindAccessibilityService)
            }
            b"android.permission.BIND_APPWIDGET" => Ok(Self::AndroidPermissionBindAppwidget),
            b"android.permission.BIND_CALL_SERVICE" => Ok(Self::AndroidPermissionBindCallService),
            b"android.permission.BIND_CARRIER_MESSAGING_SERVICE" => {
                Ok(Self::AndroidPermissionBindCarrierMessagingService)
            }
            b"android.permission.BIND_CARRIER_SERVICES" => {
                Ok(Self::AndroidPermissionBindCarrierServices)
            }
            b"android.permission.BIND_CHOOSER_TARGET_SERVICE" => {
                Ok(Self::AndroidPermissionBindChooserTargetService)
            }
            b"android.permission.BIND_DEVICE_ADMIN" => Ok(Self::AndroidPermissionBindDeviceAdmin),
            b"android.permission.BIND_DIRECTORY_SEARCH" => {
                Ok(Self::AndroidPermissionBindDirectorySearch)
            }
            b"android.permission.BIND_DREAM_SERVICE" => Ok(Self::AndroidPermissionBindDreamService),
            b"android.permission.BIND_INCALL_SERVICE" => {
                Ok(Self::AndroidPermissionBindIncallService)
            }
            b"android.permission.BIND_INPUT_METHOD" => Ok(Self::AndroidPermissionBindInputMethod),
            b"android.permission.BIND_KEYGUARD_APPWIDGET" => {
                Ok(Self::AndroidPermissionBindKeyguardAppwidget)
            }
            b"android.permission.BIND_MIDI_DEVICE_SERVICE" => {
                Ok(Self::AndroidPermissionBindMidiDeviceService)
            }
            b"android.permission.BIND_NFC_SERVICE" => Ok(Self::AndroidPermissionBindNfcService),
            b"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" => {
                Ok(Self::AndroidPermissionBindNotificationListenerService)
            }
            b"android.permission.BIND_PRINT_SERVICE" => Ok(Self::AndroidPermissionBindPrintService),
            b"android.permission.BIND_REMOTEVIEWS" => Ok(Self::AndroidPermissionBindRemoteviews),
            b"android.permission.BIND_TELECOM_CONNECTION_SERVICE" => {
                Ok(Self::AndroidPermissionBindTelecomConnectionService)
            }
            b"android.permission.BIND_TEXT_SERVICE" => Ok(Self::AndroidPermissionBindTextService),
            b"android.permission.BIND_TV_INPUT" => Ok(Self::AndroidPermissionBindTvInput),
            b"android.permission.BIND_VOICE_INTERACTION" => {
                Ok(Self::AndroidPermissionBindVoiceInteraction)
            }
            b"android.permission.BIND_VPN_SERVICE" => Ok(Self::AndroidPermissionBindVpnService),
            b"android.permission.BIND_WALLPAPER" => Ok(Self::AndroidPermissionBindWallpaper),
            b"android.permission.BLUETOOTH" => Ok(Self::AndroidPermissionBluetooth),
            b"android.permission.BLUETOOTH_ADMIN" => Ok(Self::AndroidPermissionBluetoothAdmin),
            b"android.permission.BLUETOOTH_PRIVILEGED" => {
                Ok(Self::AndroidPermissionBluetoothPrivileged)
            }
            b"android.permission.BLUETOOTH_STACK" => Ok(Self::AndroidPermissionBluetoothStack),
            b"android.permission.BODY_SENSORS" => Ok(Self::AndroidPermissionBodySensors),
            b"android.permission.BROADCAST_PACKAGE_REMOVED" => {
                Ok(Self::AndroidPermissionBroadcastPackageRemoved)
            }
            b"android.permission.BROADCAST_SMS" => Ok(Self::AndroidPermissionBroadcastSms),
            b"android.permission.BROADCAST_STICKY" => Ok(Self::AndroidPermissionBroadcastSticky),
            b"android.permission.BROADCAST_WAP_PUSH" => Ok(Self::AndroidPermissionBroadcastWapPush),
            b"android.permission.CALL_PHONE" => Ok(Self::AndroidPermissionCallPhone),
            b"android.permission.CALL_PRIVILEGED" => Ok(Self::AndroidPermissionCallPrivileged),
            b"android.permission.CAMERA" => Ok(Self::AndroidPermissionCamera),
            b"android.permission.CAMERA_DISABLE_TRANSMIT_LED" => {
                Ok(Self::AndroidPermissionCameraDisableTransmitLed)
            }
            b"android.permission.CAPTURE_AUDIO_OUTPUT" => {
                Ok(Self::AndroidPermissionCaptureAudioOutput)
            }
            b"android.permission.CAPTURE_SECURE_VIDEO_OUTPUT" => {
                Ok(Self::AndroidPermissionCaptureSecureVideoOutput)
            }
            b"android.permission.CAPTURE_VIDEO_OUTPUT" => {
                Ok(Self::AndroidPermissionCaptureVideoOutput)
            }
            b"android.permission.CHANGE_BACKGROUND_DATA_SETTING" => {
                Ok(Self::AndroidPermissionChangeBackgroundDataSetting)
            }
            b"android.permission.CHANGE_COMPONENT_ENABLED_STATE" => {
                Ok(Self::AndroidPermissionChangeComponentEnabledState)
            }
            b"android.permission.CHANGE_CONFIGURATION" => {
                Ok(Self::AndroidPermissionChangeConfiguration)
            }
            b"android.permission.CHANGE_NETWORK_STATE" => {
                Ok(Self::AndroidPermissionChangeNetworkState)
            }
            b"android.permission.CHANGE_WIMAX_STATE" => Ok(Self::AndroidPermissionChangeWimaxState),
            b"android.permission.CHANGE_WIFI_MULTICAST_STATE" => {
                Ok(Self::AndroidPermissionChangeWifiMulticastState)
            }
            b"android.permission.CHANGE_WIFI_STATE" => Ok(Self::AndroidPermissionChangeWifiState),
            b"android.permission.CLEAR_APP_CACHE" => Ok(Self::AndroidPermissionClearAppCache),
            b"android.permission.CONNECTIVITY_INTERNAL" => {
                Ok(Self::AndroidPermissionConnectivityInternal)
            }
            b"android.permission.CONTROL_LOCATION_UPDATES" => {
                Ok(Self::AndroidPermissionControlLocationUpdates)
            }
            b"android.permission.DELETE_CACHE_FILES" => Ok(Self::AndroidPermissionDeleteCacheFiles),
            b"android.permission.DELETE_PACKAGES" => Ok(Self::AndroidPermissionDeletePackages),
            b"android.permission.DIAGNOSTIC" => Ok(Self::AndroidPermissionDiagnostic),
            b"android.permission.DISABLE_KEYGUARD" => Ok(Self::AndroidPermissionDisableKeyguard),
            b"android.permission.DOWNLOAD_WITHOUT_NOTIFICATION" => {
                Ok(Self::AndroidPermissionDownloadWithoutNotification)
            }
            b"android.permission.DUMP" => Ok(Self::AndroidPermissionDump),
            b"android.permission.EXPAND_STATUS_BAR" => Ok(Self::AndroidPermissionExpandStatusBar),
            b"android.permission.FACTORY_TEST" => Ok(Self::AndroidPermissionFactoryTest),
            b"android.permission.FLASHLIGHT" => Ok(Self::AndroidPermissionFlashlight),
            b"android.permission.FORCE_STOP_PACKAGES" => {
                Ok(Self::AndroidPermissionForceStopPackages)
            }
            b"android.permission.GET_ACCOUNTS" => Ok(Self::AndroidPermissionGetAccounts),
            b"android.permission.GET_ACCOUNTS_PRIVILEGED" => {
                Ok(Self::AndroidPermissionGetAccountsPrivileged)
            }
            b"android.permission.GET_APP_OPS_STATS" => Ok(Self::AndroidPermissionGetAppOpsStats),
            b"android.permission.GET_DETAILED_TASKS" => Ok(Self::AndroidPermissionGetDetailedTasks),
            b"android.permission.GET_PACKAGE_SIZE" => Ok(Self::AndroidPermissionGetPackageSize),
            b"android.permission.GET_TASKS" => Ok(Self::AndroidPermissionGetTasks),
            b"android.permission.GLOBAL_SEARCH" => Ok(Self::AndroidPermissionGlobalSearch),
            b"android.permission.GLOBAL_SEARCH_CONTROL" => {
                Ok(Self::AndroidPermissionGlobalSearchControl)
            }
            b"android.permission.HARDWARE_TEST" => Ok(Self::AndroidPermissionHardwareTest),
            b"android.permission.INSTALL_LOCATION_PROVIDER" => {
                Ok(Self::AndroidPermissionInstallLocationProvider)
            }
            b"android.permission.INSTALL_PACKAGES" => Ok(Self::AndroidPermissionInstallPackages),
            b"android.permission.INTERACT_ACROSS_USERS" => {
                Ok(Self::AndroidPermissionInteractAcrossUsers)
            }
            b"android.permission.INTERACT_ACROSS_USERS_FULL" => {
                Ok(Self::AndroidPermissionInteractAcrossUsersFull)
            }
            b"android.permission.INTERNET" => Ok(Self::AndroidPermissionInternet),
            b"android.permission.KILL_BACKGROUND_PROCESSES" => {
                Ok(Self::AndroidPermissionKillBackgroundProcesses)
            }
            b"android.permission.LOCATION_HARDWARE" => Ok(Self::AndroidPermissionLocationHardware),
            b"android.permission.LOOP_RADIO" => Ok(Self::AndroidPermissionLoopRadio),
            b"android.permission.MANAGE_ACCOUNTS" => Ok(Self::AndroidPermissionManageAccounts),
            b"android.permission.MANAGE_ACTIVITY_STACKS" => {
                Ok(Self::AndroidPermissionManageActivityStacks)
            }
            b"android.permission.MANAGE_DOCUMENTS" => Ok(Self::AndroidPermissionManageDocuments),
            b"android.permission.MANAGE_USB" => Ok(Self::AndroidPermissionManageUsb),
            b"android.permission.MANAGE_USERS" => Ok(Self::AndroidPermissionManageUsers),
            b"android.permission.MASTER_CLEAR" => Ok(Self::AndroidPermissionMasterClear),
            b"android.permission.MEDIA_CONTENT_CONTROL" => {
                Ok(Self::AndroidPermissionMediaContentControl)
            }
            b"android.permission.MODIFY_APPWIDGET_BIND_PERMISSIONS" => {
                Ok(Self::AndroidPermissionModifyAppwidgetBindPermissions)
            }
            b"android.permission.MODIFY_AUDIO_SETTINGS" => {
                Ok(Self::AndroidPermissionModifyAudioSettings)
            }
            b"android.permission.MODIFY_PHONE_STATE" => Ok(Self::AndroidPermissionModifyPhoneState),
            b"android.permission.MOUNT_FORMAT_FILESYSTEMS" => {
                Ok(Self::AndroidPermissionMountFormatFilesystems)
            }
            b"android.permission.MOUNT_UNMOUNT_FILESYSTEMS" => {
                Ok(Self::AndroidPermissionMountUnmountFilesystems)
            }
            b"android.permission.NET_ADMIN" => Ok(Self::AndroidPermissionNetAdmin),
            b"android.permission.NET_TUNNELING" => Ok(Self::AndroidPermissionNetTunneling),
            b"android.permission.NFC" => Ok(Self::AndroidPermissionNfc),
            b"android.permission.PACKAGE_USAGE_STATS" => {
                Ok(Self::AndroidPermissionPackageUsageStats)
            }
            b"android.permission.PERSISTENT_ACTIVITY" => {
                Ok(Self::AndroidPermissionPersistentActivity)
            }
            b"android.permission.PROCESS_OUTGOING_CALLS" => {
                Ok(Self::AndroidPermissionProcessOutgoingCalls)
            }
            b"android.permission.READ_CALENDAR" => Ok(Self::AndroidPermissionReadCalendar),
            b"android.permission.READ_CALL_LOG" => Ok(Self::AndroidPermissionReadCallLog),
            b"android.permission.READ_CELL_BROADCASTS" => {
                Ok(Self::AndroidPermissionReadCellBroadcasts)
            }
            b"android.permission.READ_CONTACTS" => Ok(Self::AndroidPermissionReadContacts),
            b"android.permission.READ_DREAM_STATE" => Ok(Self::AndroidPermissionReadDreamState),
            b"android.permission.READ_EXTERNAL_STORAGE" => {
                Ok(Self::AndroidPermissionReadExternalStorage)
            }
            b"android.permission.READ_FRAME_BUFFER" => Ok(Self::AndroidPermissionReadFrameBuffer),
            b"android.permission.READ_INPUT_STATE" => Ok(Self::AndroidPermissionReadInputState),
            b"android.permission.READ_LOGS" => Ok(Self::AndroidPermissionReadLogs),
            b"android.permission.READ_PHONE_STATE" => Ok(Self::AndroidPermissionReadPhoneState),
            b"android.permission.READ_PRIVILEGED_PHONE_STATE" => {
                Ok(Self::AndroidPermissionReadPrivilegedPhoneState)
            }
            b"android.permission.READ_PROFILE" => Ok(Self::AndroidPermissionReadProfile),
            b"android.permission.READ_SMS" => Ok(Self::AndroidPermissionReadSms),
            b"android.permission.READ_SOCIAL_STREAM" => Ok(Self::AndroidPermissionReadSocialStream),
            b"android.permission.READ_SYNC_SETTINGS" => Ok(Self::AndroidPermissionReadSyncSettings),
            b"android.permission.READ_SYNC_STATS" => Ok(Self::AndroidPermissionReadSyncStats),
            b"android.permission.READ_USER_DICTIONARY" => {
                Ok(Self::AndroidPermissionReadUserDictionary)
            }
            b"android.permission.REBOOT" => Ok(Self::AndroidPermissionReboot),
            b"android.permission.RECEIVE_BOOT_COMPLETED" => {
                Ok(Self::AndroidPermissionReceiveBootCompleted)
            }
            b"android.permission.RECEIVE_DATA_ACTIVITY_CHANGE" => {
                Ok(Self::AndroidPermissionReceiveDataActivityChange)
            }
            b"android.permission.RECEIVE_EMERGENCY_BROADCAST" => {
                Ok(Self::AndroidPermissionReceiveEmergencyBroadcast)
            }
            b"android.permission.RECEIVE_MMS" => Ok(Self::AndroidPermissionReceiveMms),
            b"android.permission.RECEIVE_SMS" => Ok(Self::AndroidPermissionReceiveSms),
            b"android.permission.RECEIVE_WAP_PUSH" => Ok(Self::AndroidPermissionReceiveWapPush),
            b"android.permission.RECORD_AUDIO" => Ok(Self::AndroidPermissionRecordAudio),
            b"android.permission.REMOTE_AUDIO_PLAYBACK" => {
                Ok(Self::AndroidPermissionRemoteAudioPlayback)
            }
            b"android.permission.REMOVE_TASKS" => Ok(Self::AndroidPermissionRemoveTasks),
            b"android.permission.REORDER_TASKS" => Ok(Self::AndroidPermissionReorderTasks),
            b"android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" => {
                Ok(Self::AndroidPermissionRequestIgnoreBatteryOptimizations)
            }
            b"android.permission.REQUEST_INSTALL_PACKAGES" => {
                Ok(Self::AndroidPermissionRequestInstallPackages)
            }
            b"android.permission.RESTART_PACKAGES" => Ok(Self::AndroidPermissionRestartPackages),
            b"android.permission.RETRIEVE_WINDOW_CONTENT" => {
                Ok(Self::AndroidPermissionRetrieveWindowContent)
            }
            b"android.permission.SEND_RESPOND_VIA_MESSAGE" => {
                Ok(Self::AndroidPermissionSendRespondViaMessage)
            }
            b"android.permission.SEND_SMS" => Ok(Self::AndroidPermissionSendSms),
            b"android.permission.SET_ALWAYS_FINISH" => Ok(Self::AndroidPermissionSetAlwaysFinish),
            b"android.permission.SET_ANIMATION_SCALE" => {
                Ok(Self::AndroidPermissionSetAnimationScale)
            }
            b"android.permission.SET_DEBUG_APP" => Ok(Self::AndroidPermissionSetDebugApp),
            b"android.permission.SET_PREFERRED_APPLICATIONS" => {
                Ok(Self::AndroidPermissionSetPreferredApplications)
            }
            b"android.permission.SET_PROCESS_LIMIT" => Ok(Self::AndroidPermissionSetProcessLimit),
            b"android.permission.SET_SCREEN_COMPATIBILITY" => {
                Ok(Self::AndroidPermissionSetScreenCompatibility)
            }
            b"android.permission.SET_TIME" => Ok(Self::AndroidPermissionSetTime),
            b"android.permission.SET_TIME_ZONE" => Ok(Self::AndroidPermissionSetTimeZone),
            b"android.permission.SET_WALLPAPER" => Ok(Self::AndroidPermissionSetWallpaper),
            b"android.permission.SET_WALLPAPER_COMPONENT" => {
                Ok(Self::AndroidPermissionSetWallpaperComponent)
            }
            b"android.permission.SET_WALLPAPER_HINTS" => {
                Ok(Self::AndroidPermissionSetWallpaperHints)
            }
            b"android.permission.SIGNAL_PERSISTENT_PROCESSES" => {
                Ok(Self::AndroidPermissionSignalPersistentProcesses)
            }
            b"android.permission.START_ANY_ACTIVITY" => Ok(Self::AndroidPermissionStartAnyActivity),
            b"android.permission.STATUS_BAR" => Ok(Self::AndroidPermissionStatusBar),
            b"android.permission.SUBSCRIBED_FEEDS_READ" => {
                Ok(Self::AndroidPermissionSubscribedFeedsRead)
            }
            b"android.permission.SYSTEM_ALERT_WINDOW" => {
                Ok(Self::AndroidPermissionSystemAlertWindow)
            }
            b"android.permission.SUBSCRIBED_FEEDS_WRITE" => {
                Ok(Self::AndroidPermissionSubscribedFeedsWrite)
            }
            b"android.permission.TRANSMIT_IR" => Ok(Self::AndroidPermissionTransmitIr),
            b"android.permission.UPDATE_DEVICE_STATS" => {
                Ok(Self::AndroidPermissionUpdateDeviceStats)
            }
            b"android.permission.USE_CREDENTIALS" => Ok(Self::AndroidPermissionUseCredentials),
            b"android.permission.USE_FINGERPRINT" => Ok(Self::AndroidPermissionUseFingerprint),
            b"android.permission.USE_SIP" => Ok(Self::AndroidPermissionUseSip),
            b"android.permission.VIBRATE" => Ok(Self::AndroidPermissionVibrate),
            b"android.permission.WAKE_LOCK" => Ok(Self::AndroidPermissionWakeLock),
            b"android.permission.WRITE_APN_SETTINGS" => Ok(Self::AndroidPermissionWriteApnSettings),
            b"android.permission.WRITE_CALENDAR" => Ok(Self::AndroidPermissionWriteCalendar),
            b"android.permission.WRITE_CALL_LOG" => Ok(Self::AndroidPermissionWriteCallLog),
            b"android.permission.WRITE_CONTACTS" => Ok(Self::AndroidPermissionWriteContacts),
            b"android.permission.WRITE_DREAM_STATE" => Ok(Self::AndroidPermissionWriteDreamState),
            b"android.permission.WRITE_EXTERNAL_STORAGE" => {
                Ok(Self::AndroidPermissionWriteExternalStorage)
            }
            b"android.permission.WRITE_GSERVICES" => Ok(Self::AndroidPermissionWriteGservices),
            b"android.permission.WRITE_MEDIA_STORAGE" => {
                Ok(Self::AndroidPermissionWriteMediaStorage)
            }
            b"android.permission.WRITE_PROFILE" => Ok(Self::AndroidPermissionWriteProfile),
            b"android.permission.WRITE_SECURE_SETTINGS" => {
                Ok(Self::AndroidPermissionWriteSecureSettings)
            }
            b"android.permission.WRITE_SETTINGS" => Ok(Self::AndroidPermissionWriteSettings),
            b"android.permission.WRITE_SMS" => Ok(Self::AndroidPermissionWriteSms),
            b"android.permission.WRITE_SOCIAL_STREAM" => {
                Ok(Self::AndroidPermissionWriteSocialStream)
            }
            b"android.permission.WRITE_SYNC_SETTINGS" => {
                Ok(Self::AndroidPermissionWriteSyncSettings)
            }
            b"android.permission.WRITE_USER_DICTIONARY" => {
                Ok(Self::AndroidPermissionWriteUserDictionary)
            }
            b"com.android.alarm.permission.SET_ALARM" => {
                Ok(Self::ComAndroidAlarmPermissionSetAlarm)
            }
            b"com.android.browser.permission.READ_HISTORY_BOOKMARKS" => {
                Ok(Self::ComAndroidBrowserPermissionReadHistoryBookmarks)
            }
            b"com.android.browser.permission.WRITE_HISTORY_BOOKMARKS" => {
                Ok(Self::ComAndroidBrowserPermissionWriteHistoryBookmarks)
            }
            b"com.android.email.permission.READ_ATTACHMENT" => {
                Ok(Self::ComAndroidEmailPermissionReadAttachment)
            }
            b"com.android.launcher.permission.INSTALL_SHORTCUT" => {
                Ok(Self::ComAndroidLauncherPermissionInstallShortcut)
            }
            b"com.android.launcher.permission.PRELOAD_WORKSPACE" => {
                Ok(Self::ComAndroidLauncherPermissionPreloadWorkspace)
            }
            b"com.android.launcher.permission.READ_SETTINGS" => {
                Ok(Self::ComAndroidLauncherPermissionReadSettings)
            }
            b"com.android.launcher.permission.UNINSTALL_SHORTCUT" => {
                Ok(Self::ComAndroidLauncherPermissionUninstallShortcut)
            }
            b"com.android.launcher.permission.WRITE_SETTINGS" => {
                Ok(Self::ComAndroidLauncherPermissionWriteSettings)
            }
            b"com.android.vending.CHECK_LICENSE" => Ok(Self::ComAndroidVendingCheckLicense),
            b"com.android.voicemail.permission.ADD_VOICEMAIL" => {
                Ok(Self::ComAndroidVoicemailPermissionAddVoicemail)
            }
            b"com.android.voicemail.permission.READ_VOICEMAIL" => {
                Ok(Self::ComAndroidVoicemailPermissionReadVoicemail)
            }
            b"com.android.voicemail.permission.READ_WRITE_ALL_VOICEMAIL" => {
                Ok(Self::ComAndroidVoicemailPermissionReadWriteAllVoicemail)
            }
            b"com.android.voicemail.permission.WRITE_VOICEMAIL" => {
                Ok(Self::ComAndroidVoicemailPermissionWriteVoicemail)
            }
            b"com.google.android.c2dm.permission.RECEIVE" => {
                Ok(Self::ComGoogleAndroidC2dmPermissionReceive)
            }
            b"com.google.android.c2dm.permission.SEND" => {
                Ok(Self::ComGoogleAndroidC2dmPermissionSend)
            }
            b"com.google.android.gms.permission.ACTIVITY_RECOGNITION" => {
                Ok(Self::ComGoogleAndroidGmsPermissionActivityRecognition)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuth)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.ALL_SERVICES" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAllServices)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.OTHER_SERVICES" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthOtherServices)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.YouTubeUser" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutubeuser)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.adsense" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAdsense)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.adwords" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAdwords)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.ah" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAh)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.android" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroid)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.androidsecure" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthAndroidsecure)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.blogger" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthBlogger)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.cl" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthCl)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.cp" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthCp)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.dodgeball" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthDodgeball)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.doraemon" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthDoraemon)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.finance" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthFinance)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.gbase" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGbase)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.geowiki" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGeowiki)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.goanna_mobile" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGoannaMobile)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.grandcentral" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGrandcentral)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.groups2" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthGroups2)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.health" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthHealth)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.ig" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthIg)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.jotspot" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthJotspot)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.knol" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthKnol)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.lh2" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthLh2)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.local" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthLocal)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.mail" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthMail)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.mobile" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthMobile)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.news" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthNews)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.notebook" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthNotebook)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.orkut" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthOrkut)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.panoramio" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthPanoramio)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.print" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthPrint)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.reader" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthReader)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.sierra" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierra)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.sierraqa" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierraqa)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.sierrasandbox" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSierrasandbox)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.sitemaps" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSitemaps)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.speech" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeech)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.speechpersonalization" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthSpeechpersonalization)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.talk" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthTalk)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.wifi" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthWifi)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.wise" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthWise)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.writely" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthWritely)
            }
            b"com.google.android.googleapps.permission.GOOGLE_AUTH.youtube" => {
                Ok(Self::ComGoogleAndroidGoogleappsPermissionGoogleAuthYoutube)
            }
            b"com.google.android.gtalkservice.permission.GTALK_SERVICE" => {
                Ok(Self::ComGoogleAndroidGtalkservicePermissionGtalkService)
            }
            b"com.google.android.gtalkservice.permission.SEND_HEARTBEAT" => {
                Ok(Self::ComGoogleAndroidGtalkservicePermissionSendHeartbeat)
            }
            b"com.google.android.permission.BROADCAST_DATA_MESSAGE" => {
                Ok(Self::ComGoogleAndroidPermissionBroadcastDataMessage)
            }
            b"com.google.android.providers.gsf.permission.READ_GSERVICES" => {
                Ok(Self::ComGoogleAndroidProvidersGsfPermissionReadGservices)
            }
            b"com.google.android.providers.talk.permission.READ_ONLY" => {
                Ok(Self::ComGoogleAndroidProvidersTalkPermissionReadOnly)
            }
            b"com.google.android.providers.talk.permission.WRITE_ONLY" => {
                Ok(Self::ComGoogleAndroidProvidersTalkPermissionWriteOnly)
            }
            b"com.google.android.xmpp.permission.BROADCAST" => {
                Ok(Self::ComGoogleAndroidXmppPermissionBroadcast)
            }
            b"com.google.android.xmpp.permission.SEND_RECEIVE" => {
                Ok(Self::ComGoogleAndroidXmppPermissionSendReceive)
            }
            b"com.google.android.xmpp.permission.USE_XMPP_ENDPOINT" => {
                Ok(Self::ComGoogleAndroidXmppPermissionUseXmppEndpoint)
            }
            b"com.google.android.xmpp.permission.XMPP_ENDPOINT_BROADCAST" => {
                Ok(Self::ComGoogleAndroidXmppPermissionXmppEndpointBroadcast)
            }
            _ => bail!("unknown permission {}", str::from_utf8(s)?),
        }
    }
}

impl FromStr for Permission {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::try_from(s.as_bytes())
    }
}
