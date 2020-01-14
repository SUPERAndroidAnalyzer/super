//! Android SDK numbering scheme.

use semver::{Identifier, Version};

/// Android SDK number representation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SdkNumber {
    /// API version 1.
    Api1,
    /// API version 2.
    Api2,
    /// API version 3.
    Api3,
    /// API version 4.
    Api4,
    /// API version 5.
    Api5,
    /// API version 6.
    Api6,
    /// API version 7.
    Api7,
    /// API version 8.
    Api8,
    /// API version 9.
    Api9,
    /// API version 10.
    Api10,
    /// API version 11.
    Api11,
    /// API version 12.
    Api12,
    /// API version 13.
    Api13,
    /// API version 14.
    Api14,
    /// API version 15.
    Api15,
    /// API version 16.
    Api16,
    /// API version 17.
    Api17,
    /// API version 18.
    Api18,
    /// API version 19.
    Api19,
    /// API version 20.
    Api20,
    /// API version 21.
    Api21,
    /// API version 22.
    Api22,
    /// API version 23.
    Api23,
    /// API version 24.
    Api24,
    /// API version 25.
    Api25,
    /// API version 26.
    Api26,
    /// API version 27.
    Api27,
    /// API version 28.
    Api28,
    /// API version 29.
    Api29,

    /// Development API version.
    Development,
    /// Unknown API version.
    Unknown(u32),
}

/// Main implementation of the SDK numbers.
///
/// As per: <https://developer.android.com/reference/android/os/Build.VERSION_CODES.html>
impl SdkNumber {
    /// Gets the SDK API version number.
    pub fn number(self) -> u32 {
        match self {
            Self::Api1 => 1,
            Self::Api2 => 2,
            Self::Api3 => 3,
            Self::Api4 => 4,
            Self::Api5 => 5,
            Self::Api6 => 6,
            Self::Api7 => 7,
            Self::Api8 => 8,
            Self::Api9 => 9,
            Self::Api10 => 10,
            Self::Api11 => 11,
            Self::Api12 => 12,
            Self::Api13 => 13,
            Self::Api14 => 14,
            Self::Api15 => 15,
            Self::Api16 => 16,
            Self::Api17 => 17,
            Self::Api18 => 18,
            Self::Api19 => 19,
            Self::Api20 => 20,
            Self::Api21 => 21,
            Self::Api22 => 22,
            Self::Api23 => 23,
            Self::Api24 => 24,
            Self::Api25 => 25,
            Self::Api26 => 26,
            Self::Api27 => 27,
            Self::Api28 => 28,
            Self::Api29 => 29,

            Self::Development => 10_000,
            Self::Unknown(v) => v,
        }
    }

    /// Gets the Android version number.
    #[allow(clippy::too_many_lines)]
    pub fn version(self) -> Option<Version> {
        match self {
            Self::Api1 => Some(Version {
                major: 1,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api2 => Some(Version {
                major: 1,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api3 => Some(Version {
                major: 1,
                minor: 5,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api4 => Some(Version {
                major: 1,
                minor: 6,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api5 => Some(Version {
                major: 2,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api6 => Some(Version {
                major: 2,
                minor: 0,
                patch: 1,
                pre: vec![],
                build: vec![],
            }),
            Self::Api7 => Some(Version {
                major: 2,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api8 => Some(Version {
                major: 2,
                minor: 2,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api9 => Some(Version {
                major: 2,
                minor: 3,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api10 => Some(Version {
                major: 2,
                minor: 3,
                patch: 3,
                pre: vec![],
                build: vec![],
            }),
            Self::Api11 => Some(Version {
                major: 3,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api12 => Some(Version {
                major: 3,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api13 => Some(Version {
                major: 3,
                minor: 2,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api14 => Some(Version {
                major: 4,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api15 => Some(Version {
                major: 4,
                minor: 0,
                patch: 3,
                pre: vec![],
                build: vec![],
            }),
            Self::Api16 => Some(Version {
                major: 4,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api17 => Some(Version {
                major: 4,
                minor: 2,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api18 => Some(Version {
                major: 4,
                minor: 3,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api19 => Some(Version {
                major: 4,
                minor: 4,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api20 => Some(Version {
                major: 4,
                minor: 4,
                patch: 0,
                pre: vec![],
                build: vec![Identifier::AlphaNumeric("W".to_owned())],
            }),
            Self::Api21 => Some(Version {
                major: 5,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api22 => Some(Version {
                major: 5,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api23 => Some(Version {
                major: 6,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api24 => Some(Version {
                major: 7,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api25 => Some(Version {
                major: 7,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api26 => Some(Version {
                major: 8,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api27 => Some(Version {
                major: 8,
                minor: 1,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api28 => Some(Version {
                major: 9,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),
            Self::Api29 => Some(Version {
                major: 10,
                minor: 0,
                patch: 0,
                pre: vec![],
                build: vec![],
            }),

            Self::Development | Self::Unknown(_) => None,
        }
    }

    /// Gets the name of the Android release.
    pub fn name(&self) -> &str {
        match self {
            Self::Api1 | Self::Api2 => "Base",
            Self::Api3 => "Cupcake",
            Self::Api4 => "Donut",
            Self::Api5 | Self::Api6 => "Eclair",
            Self::Api7 => "Eclair MR1",
            Self::Api8 => "Froyo",
            Self::Api9 => "Gingerbread",
            Self::Api10 => "Gingerbread MR1",
            Self::Api11 => "Honeycomb",
            Self::Api12 => "Honeycomb MR1",
            Self::Api13 => "Honeycomb MR2",
            Self::Api14 => "Ice Cream Sandwich",
            Self::Api15 => "Ice Cream Sandwich MR1",
            Self::Api16 => "Jelly Bean",
            Self::Api17 => "Jelly Bean MR1",
            Self::Api18 => "Jelly Bean MR2",
            Self::Api19 => "KitKat",
            Self::Api20 => "KitKat Watch",
            Self::Api21 => "Lollipop",
            Self::Api22 => "Lollipop MR1",
            Self::Api23 => "Marshmallow",
            Self::Api24 => "Nougat",
            Self::Api25 => "Nougat MR1",
            Self::Api26 | Self::Api27 => "Oreo",
            Self::Api28 => "Pie",
            Self::Api29 => "Android 10",

            Self::Development => "Development",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl From<u32> for SdkNumber {
    fn from(version: u32) -> Self {
        match version {
            1 => Self::Api1,
            2 => Self::Api2,
            3 => Self::Api3,
            4 => Self::Api4,
            5 => Self::Api5,
            6 => Self::Api6,
            7 => Self::Api7,
            8 => Self::Api8,
            9 => Self::Api9,
            10 => Self::Api10,
            11 => Self::Api11,
            12 => Self::Api12,
            13 => Self::Api13,
            14 => Self::Api14,
            15 => Self::Api15,
            16 => Self::Api16,
            17 => Self::Api17,
            18 => Self::Api18,
            19 => Self::Api19,
            20 => Self::Api20,
            21 => Self::Api21,
            22 => Self::Api22,
            23 => Self::Api23,
            24 => Self::Api24,
            25 => Self::Api25,
            26 => Self::Api26,
            27 => Self::Api27,
            28 => Self::Api28,
            29 => Self::Api29,

            10_000 => Self::Development,
            t => Self::Unknown(t),
        }
    }
}

/// Prettifies the android version number so that it's shown as the official version.
pub fn prettify_android_version(version: &Version) -> String {
    format!(
        "{}{}{}{}",
        version.major,
        if version.major < 9 {
            format!(".{}", version.minor)
        } else {
            String::new()
        },
        if version.patch == 0 && version.major != 8 {
            String::new()
        } else {
            format!(".{}", version.patch)
        },
        if let Some(b) = version.build.get(0) {
            format!("{}", b)
        } else {
            String::new()
        }
    )
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity)]
mod tests {
    use super::{prettify_android_version, Identifier, SdkNumber, Version};

    /// Checks the correctness of the `SdkNumber` when transforming a `u32`.
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
        assert_eq!(SdkNumber::from(27), SdkNumber::Api27);
        assert_eq!(SdkNumber::from(28), SdkNumber::Api28);
        assert_eq!(SdkNumber::from(29), SdkNumber::Api29);

        // Unknown APIs.
        assert_eq!(SdkNumber::from(30), SdkNumber::Unknown(30));
        assert_eq!(SdkNumber::from(77), SdkNumber::Unknown(77));
        assert_eq!(SdkNumber::from(2345), SdkNumber::Unknown(2345));

        // Development API.
        assert_eq!(SdkNumber::from(10_000), SdkNumber::Development);
    }

    /// Checks the correctness back from the SDK to its number.
    #[test]
    fn it_get_number() {
        assert_eq!(SdkNumber::Api1.number(), 1);
        assert_eq!(SdkNumber::Api2.number(), 2);
        assert_eq!(SdkNumber::Api3.number(), 3);
        assert_eq!(SdkNumber::Api4.number(), 4);
        assert_eq!(SdkNumber::Api5.number(), 5);
        assert_eq!(SdkNumber::Api6.number(), 6);
        assert_eq!(SdkNumber::Api7.number(), 7);
        assert_eq!(SdkNumber::Api8.number(), 8);
        assert_eq!(SdkNumber::Api9.number(), 9);
        assert_eq!(SdkNumber::Api10.number(), 10);
        assert_eq!(SdkNumber::Api11.number(), 11);
        assert_eq!(SdkNumber::Api12.number(), 12);
        assert_eq!(SdkNumber::Api13.number(), 13);
        assert_eq!(SdkNumber::Api14.number(), 14);
        assert_eq!(SdkNumber::Api15.number(), 15);
        assert_eq!(SdkNumber::Api16.number(), 16);
        assert_eq!(SdkNumber::Api17.number(), 17);
        assert_eq!(SdkNumber::Api18.number(), 18);
        assert_eq!(SdkNumber::Api19.number(), 19);
        assert_eq!(SdkNumber::Api20.number(), 20);
        assert_eq!(SdkNumber::Api21.number(), 21);
        assert_eq!(SdkNumber::Api22.number(), 22);
        assert_eq!(SdkNumber::Api23.number(), 23);
        assert_eq!(SdkNumber::Api24.number(), 24);
        assert_eq!(SdkNumber::Api25.number(), 25);
        assert_eq!(SdkNumber::Api26.number(), 26);
        assert_eq!(SdkNumber::Api27.number(), 27);
        assert_eq!(SdkNumber::Api28.number(), 28);
        assert_eq!(SdkNumber::Api29.number(), 29);

        // Unknown APIs.
        assert_eq!(SdkNumber::Unknown(30).number(), 30);
        assert_eq!(SdkNumber::Unknown(133).number(), 133);
        assert_eq!(SdkNumber::Unknown(4392).number(), 4392);

        // Development API.
        assert_eq!(SdkNumber::Development.number(), 10_000);
    }

    /// Checks that the Android version number is correct for each API.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn it_get_version() {
        assert_eq!(
            SdkNumber::Api1.version().unwrap(),
            Version::parse("1.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api2.version().unwrap(),
            Version::parse("1.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api3.version().unwrap(),
            Version::parse("1.5.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api4.version().unwrap(),
            Version::parse("1.6.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api5.version().unwrap(),
            Version::parse("2.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api6.version().unwrap(),
            Version::parse("2.0.1").unwrap()
        );
        assert_eq!(
            SdkNumber::Api7.version().unwrap(),
            Version::parse("2.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api8.version().unwrap(),
            Version::parse("2.2.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api9.version().unwrap(),
            Version::parse("2.3.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api10.version().unwrap(),
            Version::parse("2.3.3").unwrap()
        );
        assert_eq!(
            SdkNumber::Api11.version().unwrap(),
            Version::parse("3.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api12.version().unwrap(),
            Version::parse("3.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api13.version().unwrap(),
            Version::parse("3.2.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api14.version().unwrap(),
            Version::parse("4.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api15.version().unwrap(),
            Version::parse("4.0.3").unwrap()
        );
        assert_eq!(
            SdkNumber::Api16.version().unwrap(),
            Version::parse("4.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api17.version().unwrap(),
            Version::parse("4.2.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api18.version().unwrap(),
            Version::parse("4.3.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api19.version().unwrap(),
            Version::parse("4.4.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api20.version().unwrap(),
            Version {
                major: 4,
                minor: 4,
                patch: 0,
                pre: vec![],
                build: vec![Identifier::AlphaNumeric("W".to_owned())],
            }
        );
        assert_eq!(
            SdkNumber::Api21.version().unwrap(),
            Version::parse("5.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api22.version().unwrap(),
            Version::parse("5.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api23.version().unwrap(),
            Version::parse("6.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api24.version().unwrap(),
            Version::parse("7.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api25.version().unwrap(),
            Version::parse("7.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api26.version().unwrap(),
            Version::parse("8.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api27.version().unwrap(),
            Version::parse("8.1.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api28.version().unwrap(),
            Version::parse("9.0.0").unwrap()
        );
        assert_eq!(
            SdkNumber::Api29.version().unwrap(),
            Version::parse("10.0.0").unwrap()
        );

        // Unknown APIs.
        assert!(SdkNumber::Unknown(30).version().is_none());
        assert!(SdkNumber::Unknown(201).version().is_none());
        assert!(SdkNumber::Unknown(5602).version().is_none());

        // Development API.
        assert!(SdkNumber::Development.version().is_none());
    }

    /// Checks that the names associated with API versions are correct.
    #[test]
    fn it_get_name() {
        assert_eq!(SdkNumber::Api1.name(), "Base");
        assert_eq!(SdkNumber::Api2.name(), "Base");
        assert_eq!(SdkNumber::Api3.name(), "Cupcake");
        assert_eq!(SdkNumber::Api4.name(), "Donut");
        assert_eq!(SdkNumber::Api5.name(), "Eclair");
        assert_eq!(SdkNumber::Api6.name(), "Eclair");
        assert_eq!(SdkNumber::Api7.name(), "Eclair MR1");
        assert_eq!(SdkNumber::Api8.name(), "Froyo");
        assert_eq!(SdkNumber::Api9.name(), "Gingerbread");
        assert_eq!(SdkNumber::Api10.name(), "Gingerbread MR1");
        assert_eq!(SdkNumber::Api11.name(), "Honeycomb");
        assert_eq!(SdkNumber::Api12.name(), "Honeycomb MR1");
        assert_eq!(SdkNumber::Api13.name(), "Honeycomb MR2");
        assert_eq!(SdkNumber::Api14.name(), "Ice Cream Sandwich");
        assert_eq!(SdkNumber::Api15.name(), "Ice Cream Sandwich MR1");
        assert_eq!(SdkNumber::Api16.name(), "Jelly Bean");
        assert_eq!(SdkNumber::Api17.name(), "Jelly Bean MR1");
        assert_eq!(SdkNumber::Api18.name(), "Jelly Bean MR2");
        assert_eq!(SdkNumber::Api19.name(), "KitKat");
        assert_eq!(SdkNumber::Api20.name(), "KitKat Watch");
        assert_eq!(SdkNumber::Api21.name(), "Lollipop");
        assert_eq!(SdkNumber::Api22.name(), "Lollipop MR1");
        assert_eq!(SdkNumber::Api23.name(), "Marshmallow");
        assert_eq!(SdkNumber::Api24.name(), "Nougat");
        assert_eq!(SdkNumber::Api25.name(), "Nougat MR1");
        assert_eq!(SdkNumber::Api26.name(), "Oreo");
        assert_eq!(SdkNumber::Api27.name(), "Oreo");
        assert_eq!(SdkNumber::Api28.name(), "Pie");
        assert_eq!(SdkNumber::Api29.name(), "Android 10");

        // Unknown APIs.
        assert_eq!(SdkNumber::Unknown(30).name(), "Unknown");
        assert_eq!(SdkNumber::Unknown(302).name(), "Unknown");
        assert_eq!(SdkNumber::Unknown(7302).name(), "Unknown");

        // Development API.
        assert_eq!(SdkNumber::Development.name(), "Development");
    }

    /// Checks that Android versions are properly printed.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn it_prettify_android_version() {
        assert_eq!(
            prettify_android_version(&SdkNumber::Api1.version().unwrap()),
            "1.0"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api2.version().unwrap()),
            "1.1"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api3.version().unwrap()),
            "1.5"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api4.version().unwrap()),
            "1.6"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api5.version().unwrap()),
            "2.0"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api6.version().unwrap()),
            "2.0.1"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api7.version().unwrap()),
            "2.1"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api8.version().unwrap()),
            "2.2"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api9.version().unwrap()),
            "2.3"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api10.version().unwrap()),
            "2.3.3"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api11.version().unwrap()),
            "3.0"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api12.version().unwrap()),
            "3.1"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api13.version().unwrap()),
            "3.2"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api14.version().unwrap()),
            "4.0"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api15.version().unwrap()),
            "4.0.3"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api16.version().unwrap()),
            "4.1"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api17.version().unwrap()),
            "4.2"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api18.version().unwrap()),
            "4.3"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api19.version().unwrap()),
            "4.4"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api20.version().unwrap()),
            "4.4W"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api21.version().unwrap()),
            "5.0"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api22.version().unwrap()),
            "5.1"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api23.version().unwrap()),
            "6.0"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api24.version().unwrap()),
            "7.0"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api25.version().unwrap()),
            "7.1"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api26.version().unwrap()),
            "8.0.0"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api27.version().unwrap()),
            "8.1.0"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api28.version().unwrap()),
            "9"
        );
        assert_eq!(
            prettify_android_version(&SdkNumber::Api29.version().unwrap()),
            "10"
        );
    }
}
