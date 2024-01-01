use serde::{Deserialize, Serialize};
use std::convert::From;
use std::fmt;

use crate::oids::OID;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObjectIdentifier {
    components: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Params {
    pub user: String,
    pub host: String,
    pub auth: Option<String>,
    pub auth_protocol: Option<String>,
    pub privacy: Option<String>,
    pub privacy_protocol: Option<String>,
    pub cmd: Command,
}

impl Params {
    pub const MD5_DIGEST: &'static str = "MD5";
    pub const SHA1_DIGEST: &'static str = "SHA1";
    pub const DES_ENCRYPTION: &'static str = "DES";
    pub const AES128_ENCRYPTION: &'static str = "AES128";
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Command {
    Get { oids: Vec<OID> },
    GetNext { oids: Vec<OID> },
    Walk { oid: OID },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SnmpValue {
    Int(i32),
    String(String),
    ObjectId(ObjectIdentifier),
    IpAddress([u8; 4]),
    Counter(u32),
    UnsignedInt(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    BigCounter(u64),
    Unspecified,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl From<snmp_mp::VarValue> for SnmpValue {
    fn from(item: snmp_mp::VarValue) -> SnmpValue {
        match item {
            snmp_mp::VarValue::Int(x) => SnmpValue::Int(x),
            snmp_mp::VarValue::String(x) => {
                SnmpValue::String(String::from_utf8_lossy(&x).into_owned())
            }
            snmp_mp::VarValue::ObjectId(x) => SnmpValue::ObjectId(ObjectIdentifier {
                components: x.components().to_vec(),
            }),
            snmp_mp::VarValue::IpAddress(x) => SnmpValue::IpAddress(x),
            snmp_mp::VarValue::Counter(x) => SnmpValue::Counter(x),
            snmp_mp::VarValue::UnsignedInt(x) => SnmpValue::UnsignedInt(x),
            snmp_mp::VarValue::TimeTicks(x) => SnmpValue::TimeTicks(x),
            snmp_mp::VarValue::Opaque(x) => SnmpValue::Opaque(x),
            snmp_mp::VarValue::BigCounter(x) => SnmpValue::BigCounter(x),
            snmp_mp::VarValue::Unspecified => SnmpValue::Unspecified,
            snmp_mp::VarValue::NoSuchObject => SnmpValue::NoSuchObject,
            snmp_mp::VarValue::NoSuchInstance => SnmpValue::NoSuchInstance,
            snmp_mp::VarValue::EndOfMibView => SnmpValue::EndOfMibView,
        }
    }
}

const SECONDS_IN_MINUTE: u32 = 60;
const SECONDS_IN_HOUR: u32 = 60 * SECONDS_IN_MINUTE;
const SECONDS_IN_DAY: u32 = SECONDS_IN_HOUR * 24;

impl fmt::Display for SnmpValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnmpValue::Int(x) => write!(f, "{}", x),
            SnmpValue::String(x) => write!(f, "{}", x),
            SnmpValue::ObjectId(x) => {
                let mut first = true;
                let mut retval = Err(core::fmt::Error);
                for &component in &x.components {
                    if first {
                        retval = write!(f, "{}", component);
                    } else {
                        retval = write!(f, ".{}", component);
                    }
                    first = false;
                }
                retval
            }
            SnmpValue::IpAddress(x) => write!(f, "{}.{}.{}.{}", x[0], x[1], x[2], x[3]),
            SnmpValue::Counter(x) => write!(f, "{}", x),
            SnmpValue::UnsignedInt(x) => write!(f, "{}", x),
            SnmpValue::TimeTicks(x) => {
                let hundredth = x % 100;
                let remaining_seconds = x / 100;
                let days = remaining_seconds / SECONDS_IN_DAY;
                let remaining_seconds = remaining_seconds % SECONDS_IN_DAY;

                let hours = remaining_seconds / SECONDS_IN_HOUR;
                let remaining_seconds = remaining_seconds % SECONDS_IN_HOUR;

                let minutes = remaining_seconds / SECONDS_IN_MINUTE;
                let seconds = remaining_seconds % SECONDS_IN_MINUTE;
                write!(
                    f,
                    "({}) {} day(s) {}:{:0>2}:{:0>2}.{:0>2}",
                    x, days, hours, minutes, seconds, hundredth
                )
            }
            SnmpValue::Opaque(x) => write!(f, "{:X?}", x),
            SnmpValue::BigCounter(x) => write!(f, "{}", x),
            SnmpValue::Unspecified => write!(f, "Unspecified"),
            SnmpValue::NoSuchObject => write!(f, "No such object"),
            SnmpValue::NoSuchInstance => write!(f, "No such instance"),
            SnmpValue::EndOfMibView => write!(f, "End of MIB view"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SnmpResult {
    pub host: String,
    pub oid: String,
    pub result: Option<SnmpValue>,
}

impl fmt::Display for SnmpResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OID: {}\n", self.oid)?;
        match &self.result {
            Some(x) => write!(f, "Value: {}\n", x),
            _ => write!(f, "Value <none>\n"),
        }
    }
}
