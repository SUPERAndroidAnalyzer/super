use std::fmt;
use serde::{Serialize, Serializer};


#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SDKNumber {
    Api26,
    Api25,
    Api24,
    Api23,
    Api22,
    Api21,
    Api20,
    Api19,
    Api18,
    Api17,
    Api16,
    Api15,
    Api14,
    Api13,
    Api12,
    Api11,
    Api10,
    Api9,
    Api8,
    Api7,
    Api6,
    Api5,
    Api4,
    Api3,
    Api2,
    Api1,
    ApiUnknown,
}


use self::SDKNumber::*;


/// As per: https://developer.android.com/reference/android/os/Build.VERSION_CODES.html
impl SDKNumber {
    pub fn as_str(&self) -> &str {
        match *self {
            Api26 => "Oreo (26)",
            Api25 => "Nougat MR1 (25)",
            Api24 => "Nougat (24)",
            Api23 => "Marshmallow (23)",
            Api22 => "Lollipop MR1 (22)",
            Api21 => "Lollipop (21)",
            Api20 => "KitKat Watch (20)",
            Api19 => "KitKat (19)",
            Api18 => "Jelly Bean MR2 (18)",
            Api17 => "Jelly Bean MR1 (17)",
            Api16 => "Jelly Bean (16)",
            Api15 => "Ice Cream Sandwich MR1 (15)",
            Api14 => "Ice Cream Sandwich (14)",
            Api13 => "Honeycomb MR2 (13)",
            Api12 => "Honeycomb MR1 (12)",
            Api11 => "Honeycomb (11)",
            Api10 => "Gingerbread MR1 (10)",
            Api9  => "Gingerbread (9)",
            Api8  => "Froyo (8)",
            Api7  => "Eclair MR1 (7)",
            Api6  => "Eclair 0.1 (6)",
            Api5  => "Eclair (5)",
            Api4  => "Donut (4)",
            Api3  => "Cupcake (3)",
            Api2  => "Base1.1 (2)",
            Api1  => "Base (1)",
            ApiUnknown => "Unknown (?)",
        }
    }
}

impl From<u32> for SDKNumber {
    fn from(version: u32) -> SDKNumber {
        match version {
            1  => Api1,
            2  => Api2,
            3  => Api3,
            4  => Api4,
            5  => Api5,
            6  => Api6,
            7  => Api7,
            8  => Api8,
            9  => Api9,
            10 => Api10,
            11 => Api11,
            12 => Api12,
            13 => Api13,
            14 => Api14,
            15 => Api15,
            16 => Api16,
            17 => Api17,
            18 => Api18,
            19 => Api19,
            20 => Api20,
            21 => Api21,
            22 => Api22,
            23 => Api23,
            24 => Api24,
            25 => Api25,
            26 => Api26,

            0 | _ => ApiUnknown,
        }
    }
}

impl fmt::Display for SDKNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}


impl Serialize for SDKNumber {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_str())
    }
}
