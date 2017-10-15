use std::fmt;
use serde::{Serialize, Serializer};


#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SDKVersion {
    Oreo,
    Nougat,
    Marshmallow,
    Lollipop,
    KitKat,
    JellyBean,
    IceCreamSandwich,
    Honeycomb,
    Gingerbread,
    Froyo,
    Eclair,
    Donut,
    Cupcake,
    Old,
    Unknown,
}

use self::SDKVersion::*;

impl From<u32> for SDKVersion {
    fn from(version: u32) -> Self {
        match version {
            26 => Oreo,
            25 | 24 => Nougat,
            23 => Marshmallow,
            22 | 21 => Lollipop,
            19 => KitKat,
            18 | 17 | 16 => JellyBean,
            15 | 14 => IceCreamSandwich,
            13 | 12 | 11 => Honeycomb,
            10 | 9 => Gingerbread,
            8 => Froyo,
            7 | 6 | 5 => Eclair,
            4 => Donut,
            3 => Cupcake,
            2 | 1 => Old,
            _ => Unknown,
        }
    }
}

impl From<SDKVersion> for u32 {
    fn from(version: SDKVersion) -> u32 {
        match version {
            Oreo => 26,
            Nougat => 25,
            Marshmallow => 23,
            Lollipop => 22,
            KitKat => 19,
            JellyBean => 18,
            IceCreamSandwich => 15,
            Honeycomb => 13,
            Gingerbread => 10,
            Froyo => 8,
            Eclair => 7,
            Donut => 4,
            Cupcake => 3,
            Old => 2,
            Unknown => 0,
        }
    }
}

impl fmt::Display for SDKVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match *self {
            JellyBean => "Jelly Bean".to_string(),
            IceCreamSandwich => "Ice Cream Sandwich".to_string(),
            _ => format!("{:?}", self),
        };

        write!(f, "{} ({})", string, u32::from(*self))
    }
}


impl Serialize for SDKVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}
