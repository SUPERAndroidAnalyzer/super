//! Android SDK numbering scheme.

use semver::{Version, Identifier};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SdkNumber {
    Api1,
    Api2,
    Api3,
    Api4,
    Api5,
    Api6,
    Api7,
    Api8,
    Api9,
    Api10,
    Api11,
    Api12,
    Api13,
    Api14,
    Api15,
    Api16,
    Api17,
    Api18,
    Api19,
    Api20,
    Api21,
    Api22,
    Api23,
    Api24,
    Api25,
    Api26,

    Development,
    Unknown(u32),
}

/// Main implementation of the SDK numbers.
///
/// As per: https://developer.android.com/reference/android/os/Build.VERSION_CODES.html
impl SdkNumber {
    /// Gets the SDK API version number.
    pub fn get_number(&self) -> u32 {
        match *self {
            SdkNumber::Api1 => 1,
            SdkNumber::Api2 => 2,
            SdkNumber::Api3 => 3,
            SdkNumber::Api4 => 4,
            SdkNumber::Api5 => 5,
            SdkNumber::Api6 => 6,
            SdkNumber::Api7 => 7,
            SdkNumber::Api8 => 8,
            SdkNumber::Api9 => 9,
            SdkNumber::Api10 => 10,
            SdkNumber::Api11 => 11,
            SdkNumber::Api12 => 12,
            SdkNumber::Api13 => 13,
            SdkNumber::Api14 => 14,
            SdkNumber::Api15 => 15,
            SdkNumber::Api16 => 16,
            SdkNumber::Api17 => 17,
            SdkNumber::Api18 => 18,
            SdkNumber::Api19 => 19,
            SdkNumber::Api20 => 20,
            SdkNumber::Api21 => 21,
            SdkNumber::Api22 => 22,
            SdkNumber::Api23 => 23,
            SdkNumber::Api24 => 24,
            SdkNumber::Api25 => 25,
            SdkNumber::Api26 => 26,

            SdkNumber::Development => 10_000,
            SdkNumber::Unknown(v) => v,
        }
    }

    /// Gets the Android version number.
    pub fn get_version(&self) -> Option<Version> {
        match *self {
            SdkNumber::Api1 => Some(Version {
                major: 1,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api2 => Some(Version {
                major: 1,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api3 => Some(Version {
                major: 1,
                minor: 5,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api4 => Some(Version {
                major: 1,
                minor: 6,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api5 => Some(Version {
                major: 2,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api6 => Some(Version {
                major: 2,
                minor: 0,
                patch: 1,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api7 => Some(Version {
                major: 2,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api8 => Some(Version {
                major: 2,
                minor: 2,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api9 => Some(Version {
                major: 2,
                minor: 3,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api10 => Some(Version {
                major: 2,
                minor: 3,
                patch: 3,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api11 => Some(Version {
                major: 3,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api12 => Some(Version {
                major: 3,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api13 => Some(Version {
                major: 3,
                minor: 2,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api14 => Some(Version {
                major: 4,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api15 => Some(Version {
                major: 4,
                minor: 0,
                patch: 3,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api16 => Some(Version {
                major: 4,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api17 => Some(Version {
                major: 4,
                minor: 2,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api18 => Some(Version {
                major: 4,
                minor: 3,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api19 => Some(Version {
                major: 4,
                minor: 4,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api20 => Some(Version {
                major: 4,
                minor: 4,
                patch: 0,
                pre: vec![],
                build: vec![Identifier::AlphaNumeric("W".to_owned())],
            }),
            SdkNumber::Api21 => Some(Version {
                major: 5,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api22 => Some(Version {
                major: 5,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api23 => Some(Version {
                major: 6,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api24 => Some(Version {
                major: 7,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api25 => Some(Version {
                major: 7,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            SdkNumber::Api26 => Some(Version {
                major: 8,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),

            SdkNumber::Development => None,
            SdkNumber::Unknown(_) => None,
        }
    }

    /// Gets the name of the Android release.
    pub fn get_name(&self) -> &str {
        match *self {
            SdkNumber::Api1 => "Base",
            SdkNumber::Api2 => "Base",
            SdkNumber::Api3 => "Cupcake",
            SdkNumber::Api4 => "Donut",
            SdkNumber::Api5 => "Eclair",
            SdkNumber::Api6 => "Eclair",
            SdkNumber::Api7 => "Eclair MR1",
            SdkNumber::Api8 => "Froyo",
            SdkNumber::Api9 => "Gingerbread",
            SdkNumber::Api10 => "Gingerbread MR1",
            SdkNumber::Api11 => "Honeycomb",
            SdkNumber::Api12 => "Honeycomb MR1",
            SdkNumber::Api13 => "Honeycomb MR2",
            SdkNumber::Api14 => "Ice Cream Sandwich",
            SdkNumber::Api15 => "Ice Cream Sandwich MR1",
            SdkNumber::Api16 => "Jelly Bean",
            SdkNumber::Api17 => "Jelly Bean MR1",
            SdkNumber::Api18 => "Jelly Bean MR2",
            SdkNumber::Api19 => "KitKat",
            SdkNumber::Api20 => "KitKat Watch",
            SdkNumber::Api21 => "Lollipop",
            SdkNumber::Api22 => "Lollipop MR1",
            SdkNumber::Api23 => "Marshmallow",
            SdkNumber::Api24 => "Nougat",
            SdkNumber::Api25 => "Nougat MR1",
            SdkNumber::Api26 => "Oreo",

            SdkNumber::Development => "Development",
            SdkNumber::Unknown(_) => "Unknown",
        }
    }
}

impl From<u32> for SdkNumber {
    fn from(version: u32) -> SdkNumber {
        match version {
            1 => SdkNumber::Api1,
            2 => SdkNumber::Api2,
            3 => SdkNumber::Api3,
            4 => SdkNumber::Api4,
            5 => SdkNumber::Api5,
            6 => SdkNumber::Api6,
            7 => SdkNumber::Api7,
            8 => SdkNumber::Api8,
            9 => SdkNumber::Api9,
            10 => SdkNumber::Api10,
            11 => SdkNumber::Api11,
            12 => SdkNumber::Api12,
            13 => SdkNumber::Api13,
            14 => SdkNumber::Api14,
            15 => SdkNumber::Api15,
            16 => SdkNumber::Api16,
            17 => SdkNumber::Api17,
            18 => SdkNumber::Api18,
            19 => SdkNumber::Api19,
            20 => SdkNumber::Api20,
            21 => SdkNumber::Api21,
            22 => SdkNumber::Api22,
            23 => SdkNumber::Api23,
            24 => SdkNumber::Api24,
            25 => SdkNumber::Api25,
            26 => SdkNumber::Api26,

            10_000 => SdkNumber::Development,
            t => SdkNumber::Unknown(t),
        }
    }
}

pub fn prettify_android_version(version: Version) -> String {
    format!(
        "{}.{}{}{}",
        version.major,
        version.minor,
        if version.patch != 0 {
            format!(".{}", version.patch)
        } else {
            String::new()
        },
        if let Some(b) = version.build.get(0) {
            format!("{}", b)
        } else {
            String::new()
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks the correctness of the SDKNumber when transforming a `u32`.
    #[test]
    fn it_from_u32() {
        assert_eq!(SdkNumber::from(1), SdkNumber::Api1);
        assert_eq!(SdkNumber::from(2), SdkNumber::Api2);
        assert_eq!(SdkNumber::from(3), SdkNumber::Api3);
        assert_eq!(SdkNumber::from(4), SdkNumber::Api4);
        assert_eq!(SdkNumber::from(5), SdkNumber::Api5);
        assert_eq!(SdkNumber::from(6), SdkNumber::Api6);
        assert_eq!(SdkNumber::from(7), SdkNumber::Api7);
        assert_eq!(SdkNumber::from(8), SdkNumber::Api8);
        assert_eq!(SdkNumber::from(9), SdkNumber::Api9);
        assert_eq!(SdkNumber::from(10), SdkNumber::Api10);
        assert_eq!(SdkNumber::from(11), SdkNumber::Api11);
        assert_eq!(SdkNumber::from(12), SdkNumber::Api12);
        assert_eq!(SdkNumber::from(13), SdkNumber::Api13);
        assert_eq!(SdkNumber::from(14), SdkNumber::Api14);
        assert_eq!(SdkNumber::from(15), SdkNumber::Api15);
        assert_eq!(SdkNumber::from(16), SdkNumber::Api16);
        assert_eq!(SdkNumber::from(17), SdkNumber::Api17);
        assert_eq!(SdkNumber::from(18), SdkNumber::Api18);
        assert_eq!(SdkNumber::from(19), SdkNumber::Api19);
        assert_eq!(SdkNumber::from(20), SdkNumber::Api20);
        assert_eq!(SdkNumber::from(21), SdkNumber::Api21);
        assert_eq!(SdkNumber::from(22), SdkNumber::Api22);
        assert_eq!(SdkNumber::from(23), SdkNumber::Api23);
        assert_eq!(SdkNumber::from(24), SdkNumber::Api24);
        assert_eq!(SdkNumber::from(25), SdkNumber::Api25);
        assert_eq!(SdkNumber::from(26), SdkNumber::Api26);

        // Unknown APIs.
        assert_eq!(SdkNumber::from(27), SdkNumber::Unknown(27));
        assert_eq!(SdkNumber::from(77), SdkNumber::Unknown(77));
        assert_eq!(SdkNumber::from(2345), SdkNumber::Unknown(2345));

        // Development API.
        assert_eq!(SdkNumber::from(10_000), SdkNumber::Development);
    }

    /// Checks the correctnes back from the SDK to its number.
    #[test]
    fn it_get_number() {
        assert_eq!(SdkNumber::Api1.get_number(), 1);
        assert_eq!(SdkNumber::Api2.get_number(), 2);
        assert_eq!(SdkNumber::Api3.get_number(), 3);
        assert_eq!(SdkNumber::Api4.get_number(), 4);
        assert_eq!(SdkNumber::Api5.get_number(), 5);
        assert_eq!(SdkNumber::Api6.get_number(), 6);
        assert_eq!(SdkNumber::Api7.get_number(), 7);
        assert_eq!(SdkNumber::Api8.get_number(), 8);
        assert_eq!(SdkNumber::Api9.get_number(), 9);
        assert_eq!(SdkNumber::Api10.get_number(), 10);
        assert_eq!(SdkNumber::Api11.get_number(), 11);
        assert_eq!(SdkNumber::Api12.get_number(), 12);
        assert_eq!(SdkNumber::Api13.get_number(), 13);
        assert_eq!(SdkNumber::Api14.get_number(), 14);
        assert_eq!(SdkNumber::Api15.get_number(), 15);
        assert_eq!(SdkNumber::Api16.get_number(), 16);
        assert_eq!(SdkNumber::Api17.get_number(), 17);
        assert_eq!(SdkNumber::Api18.get_number(), 18);
        assert_eq!(SdkNumber::Api19.get_number(), 19);
        assert_eq!(SdkNumber::Api20.get_number(), 20);
        assert_eq!(SdkNumber::Api21.get_number(), 21);
        assert_eq!(SdkNumber::Api22.get_number(), 22);
        assert_eq!(SdkNumber::Api23.get_number(), 23);
        assert_eq!(SdkNumber::Api24.get_number(), 24);
        assert_eq!(SdkNumber::Api25.get_number(), 25);
        assert_eq!(SdkNumber::Api26.get_number(), 26);

        // Unknown APIs.
        assert_eq!(SdkNumber::Unknown(27).get_number(), 27);
        assert_eq!(SdkNumber::Unknown(133).get_number(), 133);
        assert_eq!(SdkNumber::Unknown(4392).get_number(), 4392);

        // Development API.
        assert_eq!(SdkNumber::Development.get_number(), 10_000);
    }

    /// Checks that the Android version number is correct for each API.
    #[test]
    fn it_get_version() {
        assert_eq!(
            SdkNumber::Api1.get_version().unwrap(),
            Version::parse("1.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api2.get_version().unwrap(),
            Version::parse("1.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api3.get_version().unwrap(),
            Version::parse("1.5.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api4.get_version().unwrap(),
            Version::parse("1.6.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api5.get_version().unwrap(),
            Version::parse("2.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api6.get_version().unwrap(),
            Version::parse("2.0.1").unwrap()
        );
        assert_eq!(
            SdkNumber::Api7.get_version().unwrap(),
            Version::parse("2.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api8.get_version().unwrap(),
            Version::parse("2.2.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api9.get_version().unwrap(),
            Version::parse("2.3.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api10.get_version().unwrap(),
            Version::parse("2.3.3").unwrap()
        );
        assert_eq!(
            SdkNumber::Api11.get_version().unwrap(),
            Version::parse("3.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api12.get_version().unwrap(),
            Version::parse("3.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api13.get_version().unwrap(),
            Version::parse("3.2.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api14.get_version().unwrap(),
            Version::parse("4.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api15.get_version().unwrap(),
            Version::parse("4.0.3").unwrap()
        );
        assert_eq!(
            SdkNumber::Api16.get_version().unwrap(),
            Version::parse("4.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api17.get_version().unwrap(),
            Version::parse("4.2.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api18.get_version().unwrap(),
            Version::parse("4.3.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api19.get_version().unwrap(),
            Version::parse("4.4.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api20.get_version().unwrap(),
            Version {
                major: 4,
                minor: 4,
                patch: 0,
                pre: vec![],
                build: vec![Identifier::AlphaNumeric("W".to_owned())],
            }
        );
        assert_eq!(
            SdkNumber::Api21.get_version().unwrap(),
            Version::parse("5.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api22.get_version().unwrap(),
            Version::parse("5.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api23.get_version().unwrap(),
            Version::parse("6.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api24.get_version().unwrap(),
            Version::parse("7.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api25.get_version().unwrap(),
            Version::parse("7.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api26.get_version().unwrap(),
            Version::parse("8.0.0").unwrap()
        );

        // Unknown APIs.
        assert!(SdkNumber::Unknown(27).get_version().is_none());
        assert!(SdkNumber::Unknown(201).get_version().is_none());
        assert!(SdkNumber::Unknown(5602).get_version().is_none());

        // Development API.
        assert!(SdkNumber::Development.get_version().is_none());
    }

    /// Checks that the names associated with API versions are correct.
    #[test]
    fn it_get_name() {
        assert_eq!(SdkNumber::Api1.get_name(), "Base");
        assert_eq!(SdkNumber::Api2.get_name(), "Base");
        assert_eq!(SdkNumber::Api3.get_name(), "Cupcake");
        assert_eq!(SdkNumber::Api4.get_name(), "Donut");
        assert_eq!(SdkNumber::Api5.get_name(), "Eclair");
        assert_eq!(SdkNumber::Api6.get_name(), "Eclair");
        assert_eq!(SdkNumber::Api7.get_name(), "Eclair MR1");
        assert_eq!(SdkNumber::Api8.get_name(), "Froyo");
        assert_eq!(SdkNumber::Api9.get_name(), "Gingerbread");
        assert_eq!(SdkNumber::Api10.get_name(), "Gingerbread MR1");
        assert_eq!(SdkNumber::Api11.get_name(), "Honeycomb");
        assert_eq!(SdkNumber::Api12.get_name(), "Honeycomb MR1");
        assert_eq!(SdkNumber::Api13.get_name(), "Honeycomb MR2");
        assert_eq!(SdkNumber::Api14.get_name(), "Ice Cream Sandwich");
        assert_eq!(SdkNumber::Api15.get_name(), "Ice Cream Sandwich MR1");
        assert_eq!(SdkNumber::Api16.get_name(), "Jelly Bean");
        assert_eq!(SdkNumber::Api17.get_name(), "Jelly Bean MR1");
        assert_eq!(SdkNumber::Api18.get_name(), "Jelly Bean MR2");
        assert_eq!(SdkNumber::Api19.get_name(), "KitKat");
        assert_eq!(SdkNumber::Api20.get_name(), "KitKat Watch");
        assert_eq!(SdkNumber::Api21.get_name(), "Lollipop");
        assert_eq!(SdkNumber::Api22.get_name(), "Lollipop MR1");
        assert_eq!(SdkNumber::Api23.get_name(), "Marshmallow");
        assert_eq!(SdkNumber::Api24.get_name(), "Nougat");
        assert_eq!(SdkNumber::Api25.get_name(), "Nougat MR1");
        assert_eq!(SdkNumber::Api26.get_name(), "Oreo");

        // Unknown APIs.
        assert_eq!(SdkNumber::Unknown(27).get_name(), "Unknown");
        assert_eq!(SdkNumber::Unknown(302).get_name(), "Unknown");
        assert_eq!(SdkNumber::Unknown(7302).get_name(), "Unknown");

        // Development API.
        assert_eq!(SdkNumber::Development.get_name(), "Development");
    }

    /// Checks that Android versions are properly printed.
    #[test]
    fn it_prettify_android_version() {
        assert_eq!(
            prettify_android_version(SdkNumber::Api1.get_version().unwrap()),
            "1.0"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api2.get_version().unwrap()),
            "1.1"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api3.get_version().unwrap()),
            "1.5"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api4.get_version().unwrap()),
            "1.6"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api5.get_version().unwrap()),
            "2.0"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api6.get_version().unwrap()),
            "2.0.1"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api7.get_version().unwrap()),
            "2.1"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api8.get_version().unwrap()),
            "2.2"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api9.get_version().unwrap()),
            "2.3"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api10.get_version().unwrap()),
            "2.3.3"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api11.get_version().unwrap()),
            "3.0"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api12.get_version().unwrap()),
            "3.1"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api13.get_version().unwrap()),
            "3.2"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api14.get_version().unwrap()),
            "4.0"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api15.get_version().unwrap()),
            "4.0.3"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api16.get_version().unwrap()),
            "4.1"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api17.get_version().unwrap()),
            "4.2"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api18.get_version().unwrap()),
            "4.3"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api19.get_version().unwrap()),
            "4.4"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api20.get_version().unwrap()),
            "4.4W"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api21.get_version().unwrap()),
            "5.0"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api22.get_version().unwrap()),
            "5.1"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api23.get_version().unwrap()),
            "6.0"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api24.get_version().unwrap()),
            "7.0"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api25.get_version().unwrap()),
            "7.1"
        );
        assert_eq!(
            prettify_android_version(SdkNumber::Api26.get_version().unwrap()),
            "8.0"
        );
    }
}
