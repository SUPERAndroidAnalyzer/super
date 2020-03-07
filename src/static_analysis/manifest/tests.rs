//! Tests for the manifest.

use super::{get_line, InstallLocation, Permission, PermissionChecklist};
use std::str::FromStr;

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
    assert!(get_line(code3, "non-matching").is_none());
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
