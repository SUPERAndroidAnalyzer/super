use std::fs::File;
use std::path::Path;
use std::str::FromStr;

use xml::reader::{EventReader, XmlEvent};
use xml::ParserConfig;
use colored::Colorize;

use {Error, Result, Criticity, DOWNLOAD_FOLDER, DIST_FOLDER, RESULTS_FOLDER, print_error,
     print_warning, print_vulnerability};
use results::Results;

const PARSER_CONFIG: ParserConfig = ParserConfig {
    trim_whitespace: true,
    whitespace_to_characters: false,
    cdata_to_characters: false,
    ignore_comments: true,
    coalesce_characters: true,
};


pub fn manifest_analysis(app_id: &str,
                         verbose: bool,
                         quiet: bool,
                         force: bool,
                         results: &mut Results) {
    if verbose {
        println!("Loading the manifest file. For this, we first parse the document and then we'll \
                  analize it.")
    }

    let manifest = match Manifest::load(format!("{}/{}/AndroidManifest.xml",
                                                DIST_FOLDER,
                                                app_id),
                                        verbose) {
        Ok(m) => {
            if verbose {
                println!("{}", "The manifest was loaded successfully!".green());
                println!("");
            }
            m
        }
        Err(e) => {
            print_error(format!("There was an error when loading the manifest: {}", e),
                        verbose);
            if verbose {
                println!("The rest of the analysis will continue, but there will be no analysis \
                          of the AndroidManifest.xml file.");
            }
            return;
        }
    };

    if manifest.get_package() != app_id {
        print_warning(format!("Seems that the package in the AndroidManifest.xml is not the \
                               same as the application ID provided. Provided application id: \
                               {}, manifest package: {}",
                              app_id,
                              manifest.get_package()),
                      verbose);

        if verbose {
            println!("This does not mean that something is bad, but it's supposed to have the \
                      application in the format {{package}}.apk in the {} folder and use the \
                      package as the application ID for this auditor.",
                     DOWNLOAD_FOLDER);
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

        results.add_vulnerability("Manifest Debug",
                                  description,
                                  Some("AndroidManifest.xml"),
                                  None,
                                  criticity);
        if verbose {
            print_vulnerability(description, criticity);
        }
    }

    if manifest.needs_large_heap() {
        let criticity = Criticity::Low;
        let description = "The application needs a large heap. This is not a vulnerability \
                             as such, but could be in devices with small heap. Review if the \
                             large heap is actually needed.";

        results.add_vulnerability("Large heap",
                                  description,
                                  Some("AndroidManifest.xml"),
                                  None,
                                  criticity);
        if verbose {
            print_vulnerability(description, criticity);
        }
    }

    if manifest.get_permission_checklist().needs_permission(Permission::Internet) {
        let criticity = Criticity::Low;
        let description = "The application needs Internet access. This is not a \
                             vulnerability as such, but it needs aditional security measures \
                             if it's being connected to the Internet. Check if the \
                             permission is actually needed.";

        results.add_vulnerability("Internet permission",
                                  description,
                                  Some("AndroidManifest.xml"),
                                  None,
                                  criticity);

        if verbose {
            print_vulnerability(description, criticity);
        }
    }

    if manifest.get_permission_checklist().needs_permission(Permission::WriteExternalStorage) {
        let criticity = Criticity::Medium;
        let description = "The application needs external storage access. This could be a \
                             security issue if those accesses are not controled.";

        results.add_vulnerability("External storage write permission",
                                  description,
                                  Some("AndroidManifest.xml"),
                                  None,
                                  criticity);

        if verbose {
            print_vulnerability(description, criticity);
        }
    }

    if verbose {
        println!("");
        println!("{}", "The manifest was analized correctly!".green());
        println!("The results have been stored in {}/{}/manifest_results.txt",
                 RESULTS_FOLDER,
                 app_id);
    } else if !quiet {
        println!("Manifest analyzed.");
    }
}

struct Manifest {
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
        let file = try!(File::open(path));
        let parser = EventReader::new_with_config(file, PARSER_CONFIG);
        let mut manifest: Manifest = Default::default();

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
                                                print_warning(format!("An error occurred \
                                                                       when parsing a \
                                                                       permission in \
                                                                       the manifest: \
                                                                       {}.\nThe process \
                                                                       will continue, though.",
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
    internet: bool,
    write_external_storage: bool,
}

impl PermissionChecklist {
    pub fn needs_permission(&self, p: Permission) -> bool {
        match p {
            Permission::AccessCheckinProperties => self.access_checkin_properties,
            Permission::AccessCoarseLocation => self.access_coarse_location,
            Permission::AccessFineLocation => self.access_fine_location,
            Permission::AccessLocationExtraCommands => self.access_location_extra_commands,
            Permission::Internet => self.internet,
            Permission::WriteExternalStorage => self.write_external_storage,
        }
    }

    fn set_needs_permission(&mut self, p: Permission) {
        match p {
            Permission::AccessCheckinProperties => self.access_checkin_properties = true,
            Permission::AccessCoarseLocation => self.access_coarse_location = true,
            Permission::AccessFineLocation => self.access_fine_location = true,
            Permission::AccessLocationExtraCommands => self.access_location_extra_commands = true,
            Permission::Internet => self.internet = true,
            Permission::WriteExternalStorage => self.write_external_storage = true,
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
            internet: false,
            write_external_storage: false,
        }
    }
}

enum Permission {
    AccessCheckinProperties,
    AccessCoarseLocation,
    AccessFineLocation,
    AccessLocationExtraCommands,
    Internet,
    WriteExternalStorage,
}

impl FromStr for Permission {
    type Err = Error;
    fn from_str(s: &str) -> Result<Permission> {
        match s {
            "ACCESS_CHECKIN_PROPERTIES" => Ok(Permission::AccessCheckinProperties),
            "ACCESS_COARSE_LOCATION" => Ok(Permission::AccessCoarseLocation),
            "ACCESS_FINE_LOCATION" => Ok(Permission::AccessFineLocation),
            "ACCESS_LOCATION_EXTRA_COMMANDS" => Ok(Permission::AccessLocationExtraCommands),
            "INTERNET" => Ok(Permission::Internet),
            "WRITE_EXTERNAL_STORAGE" => Ok(Permission::WriteExternalStorage),
            _ => Err(Error::ParseError),
        }
    }
}
