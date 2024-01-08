#![feature(vec_into_raw_parts)]

use anyhow::Result;
use k0hax_snmpv3;
use std::ffi::{c_char, c_void, CStr, CString};
use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
/// AuthTypeArgs communicates which authentication mechanism will be used
/// for the session.
///
/// Note: NoAuth is not implemented yet.
pub enum AuthTypeArgs {
    Md5Digest,
    Sha1Digest,
    NoAuth,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
/// PrivTypeArgs communicates which encryption mechanism will be used
/// for the session.
///
/// Note: NoPriv is not implemented yet.
pub enum PrivTypeArgs {
    Des,
    Aes128,
    NoPriv,
}

#[derive(Debug, Clone)]
/// The OidMap contains a list of OIDs that can be used to
/// reverse the dotted decimal OIDs back to human readable OIDs
pub struct OidMap {
    pub oids: Vec<OID>,
}

impl From<k0hax_snmpv3::oids::OidMap> for OidMap {
    fn from(item: k0hax_snmpv3::oids::OidMap) -> OidMap {
        let mut retval: OidMap = OidMap { oids: Vec::new() };
        for oid in item.oids {
            retval.oids.push(oid.into());
        }
        retval
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
/// The OID struct contains a dotted decimal, ex: "0.1.2.3" `oid`, and a human readable
/// C string `name`. These are used both for the OidMap, and for telling the library
/// what OIDs to Get or Walk.
pub struct OID {
    pub oid: *const c_char,
    pub name: *const c_char,
}

impl OID {
    fn get_oid_string(&self) -> String {
        unsafe {
            assert!(!self.oid.is_null());
            String::from_utf8_lossy(CStr::from_ptr(&*self.oid).to_bytes()).to_string()
        }
    }

    fn get_name_string(&self) -> String {
        unsafe {
            assert!(!self.name.is_null());
            String::from_utf8_lossy(CStr::from_ptr(&*self.name).to_bytes()).to_string()
        }
    }
}

impl From<k0hax_snmpv3::oids::OID> for OID {
    fn from(item: k0hax_snmpv3::oids::OID) -> OID {
        let oid_cstr = CString::new(item.oid).expect("CString::new failed");
        let oid_ptr = oid_cstr.into_raw();

        let name_cstr = CString::new(item.name).expect("CString::new failed");
        let name_ptr = name_cstr.into_raw();
        OID {
            oid: oid_ptr,
            name: name_ptr,
        }
    }
}

impl fmt::Display for OID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let oid_cstr = unsafe {
            assert!(!self.oid.is_null());
            CStr::from_ptr(&*self.oid)
        };
        let name_cstr = unsafe {
            assert!(!self.name.is_null());
            CStr::from_ptr(&*self.name)
        };
        let oid_str = String::from_utf8_lossy(oid_cstr.to_bytes()).to_string();
        let name_str = String::from_utf8_lossy(name_cstr.to_bytes()).to_string();
        write!(f, "{} : {}", oid_str, name_str)
    }
}

impl fmt::Debug for OID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let oid_cstr = unsafe {
            assert!(!self.oid.is_null());
            CStr::from_ptr(&*self.oid)
        };
        let name_cstr = unsafe {
            assert!(!self.name.is_null());
            CStr::from_ptr(&*self.name)
        };
        let oid_str = String::from_utf8_lossy(oid_cstr.to_bytes()).to_string();
        let name_str = String::from_utf8_lossy(name_cstr.to_bytes()).to_string();
        write!(f, "\"{}\": \"{}\"", oid_str, name_str)
    }
}

/// The struct that C sends to the library, for Auth values.
#[derive(Debug)]
#[repr(C)]
pub struct AuthParams {
    auth_protocol: AuthTypeArgs,
    auth_secret: *const c_char,
}

/// The struct that C sends to the library, for encryption values.
#[derive(Debug)]
#[repr(C)]
pub struct PrivParams {
    pub priv_protocol: PrivTypeArgs,
    pub priv_secret: *const c_char,
}

/// A struct with everything needed to run an SNMPv3 command.
#[repr(C)]
pub struct Params {
    pub user: *const c_char,
    pub host: *const c_char,
    pub auth_params: *mut AuthParams,
    pub priv_params: *mut PrivParams,
    pub cmd: *mut Command,
}

impl fmt::Debug for Params {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let user_cstr = unsafe {
            assert!(!self.user.is_null());
            CStr::from_ptr(&*self.user)
        };
        let user = String::from_utf8_lossy(user_cstr.to_bytes()).to_string();

        let host_cstr = unsafe {
            assert!(!self.host.is_null());
            CStr::from_ptr(&*self.host)
        };
        let host = String::from_utf8_lossy(host_cstr.to_bytes()).to_string();

        let auth_ptr = unsafe { &*self.auth_params };
        let priv_ptr = unsafe { &*self.priv_params };
        let cmd_ptr = unsafe { &*self.cmd };

        write!(f, "User: {}\n", user)?;
        write!(f, "Host: {}\n", host)?;
        write!(f, "Auth Params: {:?}\n", auth_ptr)?;
        write!(f, "Priv Params: {:?}\n", priv_ptr)?;
        write!(f, "Command: {:?}\n", cmd_ptr)
    }
}

/// A struct to return to C with the results of the SNMPv3 command.
///
/// `host` is the hostname that this result came from.
///
/// `oid` is the OID that this result came from.
///
/// `length` and `capacity` are used both to allow C to parse the `result`,
/// and because Rust needs those values to convert a pointer back into
/// certain data types, such as `Vec<T>`.
///
/// `result_type` is used by C to determine what kind of data was returned.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct SnmpResult {
    pub host: *mut c_char,
    pub oid: *mut c_char,
    pub result_type: SnmpType,
    pub length: usize,
    pub capacity: usize,
    pub result: *mut c_void,
}

/// A struct to return to C with an array of results of the SNMPv3 command.
///
/// `length` and `capacity` are used both to allow C to parse the `results`,
/// by providing C with the length of the SnmpResult array, and because
/// Rust will need those values to convert the results pointer back into a
/// Vec<*mut SnmpResult> in order to free the results.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct SnmpResults {
    pub length: usize,
    pub capacity: usize,
    pub results: *mut *mut SnmpResult,
}

/// The ObjectIdentifier struct is just a datatype for SNMP return values
/// of type ObjectId.
///
/// Components is an array of u64 (uint64_t in C) values, the length of the array
/// is stored in `length`.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ObjectIdentifier {
    pub length: usize,
    pub capacity: usize,
    pub components: *mut u64,
}

/// This will allow C programs to read the correct SnmpValue type
///
/// These values can be used to match SnmpResult->result_type to the correct
/// data type.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum SnmpType {
    Int,
    String,
    ObjectId,
    IpAddress,
    Counter,
    UnsignedInt,
    TimeTicks,
    Opaque,
    BigCounter,
    Unspecified,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

/// This enum is so that C can identify the type of each `SnmpValue`.
///
/// These are used to actually store values, it is converted to a void pointer
/// when we send it to C.
#[repr(C)]
pub enum SnmpValue {
    Int(i32),
    String(*mut c_char),
    ObjectId(*mut ObjectIdentifier),
    IpAddress([u8; 4]),
    Counter(u32),
    UnsignedInt(u32),
    TimeTicks(u32),
    Opaque(Box<Vec<u8>>),
    BigCounter(u64),
    Unspecified,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

/// This enum is a duplicate of `params::Command`, but exported to C
///
/// The command types have different parameters.
///
/// Get.oid is a single OID.
///
/// GetNext.oids is a list of OIDs (an OidMap).
///
/// Walk.oid is a single OID.
#[repr(C)]
pub enum Command {
    Get { oid: *const OID },
    GetNext { oids: *const OID },
    Walk { oid: *const OID },
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Command::Get { oid: x } => {
                assert!(!x.is_null());
                let oid = unsafe { &**x };
                write!(f, "Get {{ oid: {:#?} }}", oid)
            }
            Command::GetNext { oids: x } => {
                assert!(!x.is_null());
                let oids = unsafe { &**x };
                write!(f, "GetNext {{ oids: {:#?} }}", oids)
            }
            Command::Walk { oid: x } => {
                assert!(!x.is_null());
                let oid = unsafe { &**x };
                write!(f, "Walk {{ oid: {:#?} }}", oid)
            }
        }
    }
}

/* Begin OidMap */
/// Ask Rust to allocate and return a pointer to a new OidMap.
///
/// Returns a void pointer, which is the OidMap.
///
/// This void pointer can not be dereferenced by C, it is just
/// used as an opaque pointer that can be passed back to Rust later.
#[no_mangle]
pub unsafe extern "C" fn new_oid_map() -> *mut c_void {
    let oid_map: OidMap = OidMap { oids: Vec::new() };
    Box::into_raw(Box::new(oid_map)) as *mut c_void
}

/// Ask Rust to push an OID struct onto the OidMap.
///
/// This has to be a function because the OidMap is an opaque pointer for C,
/// and only Rust can modify it.
#[no_mangle]
pub unsafe extern "C" fn insert_oid_map(oid_ptr: *mut OID, ptr: *mut c_void) {
    assert!(!ptr.is_null());
    assert!(!oid_ptr.is_null());
    let oid_map_ptr = ptr as *mut OidMap;
    let oid_map: &mut OidMap = unsafe { &mut *oid_map_ptr };
    let oid: &OID = unsafe { &*oid_ptr };
    oid_map.oids.push(*oid);
}

/// A convenience function to print the current value of the
/// OidMap.
///
/// This does not consume the OidMap.
#[no_mangle]
pub unsafe extern "C" fn print_oid_map(ptr: *mut c_void) {
    assert!(!ptr.is_null());
    let oid_map_ptr = ptr as *mut OidMap;
    let oid_map: &OidMap = unsafe { &*oid_map_ptr };
    println!("{:#?}", oid_map);
}

/// Ask Rust to free the OidMap.
///
/// C is unable to free the memory used by the OidMap, so this function will
/// perform that task.
#[no_mangle]
pub unsafe extern "C" fn free_oid_map(ptr: *mut c_void) {
    assert!(!ptr.is_null());
    let _ = Box::from_raw(ptr as *mut OidMap);
}
/* End OidMap */

/* Begin Command */
/// Convenience function to print the contents of the Command struct.
#[no_mangle]
pub unsafe extern "C" fn print_command(ptr: *mut Command) {
    assert!(!ptr.is_null());
    let cmd_ptr = &*ptr;
    println!("{:?}", &cmd_ptr);
}
/* End Command */

/* Begin Auth */
/// Convenience function to print the contents of the AuthParams struct.
#[no_mangle]
pub unsafe extern "C" fn print_auth(ptr: *mut AuthParams) {
    let auth = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };
    let auth_secret_cstr = unsafe {
        assert!(!auth.auth_secret.is_null());
        CStr::from_ptr(&*auth.auth_secret)
    };
    let auth_secret = String::from_utf8_lossy(auth_secret_cstr.to_bytes()).to_string();
    println!("{:?}", &auth);
    println!("{:?}", &auth_secret);
}
/* End Auth */

/* Begin Priv */
/// Convenience function to print the contents of the PrivParams struct.
#[no_mangle]
pub unsafe extern "C" fn print_priv(ptr: *mut PrivParams) {
    let priv_v = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };
    let priv_secret_cstr = unsafe {
        assert!(!priv_v.priv_secret.is_null());
        CStr::from_ptr(&*priv_v.priv_secret)
    };
    let priv_secret = String::from_utf8_lossy(priv_secret_cstr.to_bytes()).to_string();
    println!("{:?}", priv_v);
    println!("Priv Secret: {}", priv_secret);
}
/* End Priv */

/* Begin Params */
/// Convenience function to print the contents of the Params struct.
#[no_mangle]
pub unsafe extern "C" fn print_params(ptr: *mut Params) {
    let param_ptr = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };
    println!("{:?}", param_ptr);
}
/* End Params */

/// This converts an OID dotted decimal string, ex: "0.1.2.3" to a "real" OID Object.
///
/// For library-internal use.
fn oid_from_strings(oid_str: String, oid_name: String) -> k0hax_snmpv3::oids::OID {
    k0hax_snmpv3::oids::OID {
        oid: oid_str,
        name: oid_name,
    }
}

/// This takes an SnmpResult from the parent k0hax_snmpv3 library, and
/// converts it to our own SnmpResult struct so that we can return it to C
/// properly.
fn to_c_snmp_result(item: k0hax_snmpv3::params::SnmpResult) -> SnmpResult {
    let host = CString::new(item.host).unwrap();
    let oid = CString::new(item.oid).unwrap();
    let result_intermediate = match item.result {
        Some(x) => x,
        None => panic!("No SnmpValue in SnmpResult!"),
    };
    let mut length: usize = 0;
    let mut capacity: usize = 0;
    let return_type;
    let result = match result_intermediate {
        k0hax_snmpv3::params::SnmpValue::Int(x) => {
            return_type = SnmpType::Int;
            let int_ret: *mut i32 = Box::into_raw(Box::new(x));
            int_ret as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::String(x) => {
            length = x.len();
            return_type = SnmpType::String;
            CString::new(x).unwrap().into_raw() as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::ObjectId(x) => {
            return_type = SnmpType::ObjectId;
            let (components, oid_length, oid_capacity) = x.components.into_raw_parts();
            Box::into_raw(Box::new({
                ObjectIdentifier {
                    length: oid_length,
                    capacity: oid_capacity,
                    components: components,
                }
            })) as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::IpAddress(x) => {
            return_type = SnmpType::IpAddress;
            let ip_ret: *mut [u8; 4] = Box::into_raw(Box::new(x));
            ip_ret as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::Counter(x) => {
            return_type = SnmpType::Counter;
            let counter_ret: *mut u32 = Box::into_raw(Box::new(x));
            counter_ret as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::UnsignedInt(x) => {
            return_type = SnmpType::UnsignedInt;
            let unsigned_int_ret: *mut u32 = Box::into_raw(Box::new(x));
            unsigned_int_ret as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::TimeTicks(x) => {
            return_type = SnmpType::TimeTicks;
            let retval: *mut u32 = Box::into_raw(Box::new(x));
            retval as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::Opaque(x) => {
            return_type = SnmpType::Opaque;
            let (opaque_value, opaque_len, opaque_cap) = x.into_raw_parts();
            length = opaque_len;
            capacity = opaque_cap;
            opaque_value as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::BigCounter(x) => {
            return_type = SnmpType::BigCounter;
            let big_counter_ret: *mut u64 = Box::into_raw(Box::new(x));
            big_counter_ret as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::Unspecified => {
            return_type = SnmpType::Unspecified;
            Box::into_raw(Box::new(SnmpValue::Unspecified)) as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::NoSuchObject => {
            return_type = SnmpType::NoSuchObject;
            Box::into_raw(Box::new(SnmpValue::NoSuchObject)) as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::NoSuchInstance => {
            return_type = SnmpType::NoSuchInstance;
            Box::into_raw(Box::new(SnmpValue::NoSuchInstance)) as *mut c_void
        }
        k0hax_snmpv3::params::SnmpValue::EndOfMibView => {
            return_type = SnmpType::EndOfMibView;
            Box::into_raw(Box::new(SnmpValue::EndOfMibView)) as *mut c_void
        }
    };
    SnmpResult {
        host: host.into_raw(),
        oid: oid.into_raw(),
        length: length,
        capacity: capacity,
        result_type: return_type,
        result: result,
    }
}

/// A private convenience function to free CStrings from C.
fn free_cstring(item: *mut c_char) {
    let _ = unsafe {
        let _ = CString::from_raw(item);
    };
}

/// Ask Rust to free an SnmpResult.
///
/// C is not able to properly free SnmpResult, so it must call this function when it would
/// otherwise call free() on the SnmpResult.
#[no_mangle]
pub unsafe extern "C" fn free_snmp_result(ptr: *mut SnmpResult) {
    assert!(!ptr.is_null());
    let result = Box::from_raw(ptr);
    free_cstring(result.host);
    free_cstring(result.oid);
    let inner_result_ptr = result.result as *mut SnmpValue;
    let inner_result = Box::from_raw(inner_result_ptr);
    match *inner_result {
        SnmpValue::String(x) => free_cstring(x),
        SnmpValue::ObjectId(x) => unsafe {
            let _: Box<Vec<u64>> = Box::new(Vec::<u64>::from_raw_parts(
                (*x).components as *mut u64,
                (*x).length,
                (*x).capacity,
            ));
        },
        _ => (),
    };
}

/// Ask Rust to free a SnmpResults (plural form of the struct)
///
/// C is not able to properly free SnmpResults, so it must call this function when it would
/// otherwise call free() on the SnmpResults.
///
/// This function will free all child SnmpResult structs within the SnmpResults as well.
#[no_mangle]
pub unsafe extern "C" fn free_snmp_results(ptr: *mut SnmpResults) {
    assert!(!ptr.is_null());
    let results_ptr = Box::from_raw(ptr);
    let results_results = results_ptr.results;
    let p_snmpresult: Vec<*mut SnmpResult> = unsafe {
        Vec::<*mut SnmpResult>::from_raw_parts(
            results_results,
            results_ptr.length,
            results_ptr.capacity,
        )
    };
    let _ = free_snmpresult_vec(p_snmpresult).unwrap();
}

/// A private convenience function used by free_snmp_results to free each internal SnmpResult
fn free_snmpresult_vec(p_snmpresult: Vec<*mut SnmpResult>) -> Result<()> {
    for ptr_snmp_result in p_snmpresult {
        assert!(!ptr_snmp_result.is_null());
        let result: Box<SnmpResult> = unsafe { Box::from_raw(ptr_snmp_result) };
        free_cstring(result.host);
        free_cstring(result.oid);
        match result.result_type {
            SnmpType::Int => unsafe {
                let _: i32 = *Box::from_raw(result.result as *mut i32);
            },
            SnmpType::String => {
                free_cstring(result.result as *mut c_char);
            }
            SnmpType::ObjectId => unsafe {
                free_object_identifier(Box::from_raw(result.result as *mut ObjectIdentifier));
            },
            SnmpType::IpAddress => unsafe {
                let _: [u8; 4] = *Box::from_raw(result.result as *mut [u8; 4]);
            },
            SnmpType::Counter => unsafe {
                let _: u32 = *Box::from_raw(result.result as *mut u32);
            },
            SnmpType::UnsignedInt => unsafe {
                let _: u32 = *Box::from_raw(result.result as *mut u32);
            },
            SnmpType::TimeTicks => unsafe {
                let _: u32 = *Box::from_raw(result.result as *mut u32);
            },
            SnmpType::Opaque => unsafe {
                let _: Box<Vec<u8>> = Box::new(Vec::<u8>::from_raw_parts(
                    result.result as *mut u8,
                    result.length,
                    result.capacity,
                ));
            },
            SnmpType::BigCounter => unsafe {
                let _: u64 = *Box::from_raw(result.result as *mut u64);
            },
            SnmpType::Unspecified => (),
            SnmpType::NoSuchObject => (),
            SnmpType::NoSuchInstance => (),
            SnmpType::EndOfMibView => (),
        }
    }
    Ok(())
}

/// Ask Rust to free an ObjectIdentifier.
///
/// This should only be used if the ObjectIdentifier is returned from Rust. If it is created by C
/// by using malloc() then C should free it, not Rust.
#[no_mangle]
pub unsafe extern "C" fn free_object_identifier(ptr: Box<ObjectIdentifier>) {
    assert!(!ptr.components.is_null());
    let _ = unsafe { Vec::<u64>::from_raw_parts(ptr.components, ptr.length, ptr.capacity) };
}

/// The "do the ting" function.
///
/// This function takes a *OidMap `oid_map_ptr`, and a *Params as `param_ptr` and
/// returns *SnmpResults.
///
/// This function does all the heavy lifting, and is probably where optimization work could have
/// the most impact.
#[no_mangle]
pub unsafe extern "C" fn run(oid_map_ptr: *mut c_void, param_ptr: *mut Params) -> *mut SnmpResults {
    assert!(!oid_map_ptr.is_null());
    assert!(!param_ptr.is_null());
    let oid_map_real_ptr = oid_map_ptr as *mut OidMap;
    let oid_map: &mut OidMap = unsafe { &mut *oid_map_real_ptr };
    let mut oid_vec: Vec<k0hax_snmpv3::oids::OID> = Vec::new();

    for oid in &(*oid_map).oids {
        let t_oid_string: String = oid.get_oid_string();
        let t_name_string: String = oid.get_name_string();

        let this_oid = oid_from_strings(t_oid_string, t_name_string);
        oid_vec.push(this_oid.into());
    }

    let k0hax_oid_map: k0hax_snmpv3::oids::OidMap = k0hax_snmpv3::oids::OidMap {
        oids: oid_vec.clone(),
    };

    let params = unsafe { &*param_ptr };

    let user_cstr = unsafe {
        assert!(!params.user.is_null());
        CStr::from_ptr(&*params.user)
    };
    let user = String::from_utf8_lossy(user_cstr.to_bytes()).to_string();

    let host_cstr = unsafe {
        assert!(!params.host.is_null());
        CStr::from_ptr(&*params.host)
    };
    let hostname = String::from_utf8_lossy(host_cstr.to_bytes()).to_string();

    /* Begin Auth */
    let auth_params = unsafe {
        assert!(!params.auth_params.is_null());
        &*params.auth_params
    };

    let auth_secret_cstr = unsafe {
        assert!(!auth_params.auth_secret.is_null());
        CStr::from_ptr(&*auth_params.auth_secret)
    };
    let auth_secret = String::from_utf8_lossy(auth_secret_cstr.to_bytes()).to_string();

    let auth_protocol = match auth_params.auth_protocol {
        AuthTypeArgs::Md5Digest => Some(k0hax_snmpv3::params::Params::MD5_DIGEST.to_string()),
        AuthTypeArgs::Sha1Digest => Some(k0hax_snmpv3::params::Params::SHA1_DIGEST.to_string()),
        AuthTypeArgs::NoAuth => None,
    };
    /* End Auth */

    /* Begin Priv */
    let priv_params = unsafe {
        assert!(!params.priv_params.is_null());
        &*params.priv_params
    };

    let priv_secret_cstr = unsafe {
        assert!(!priv_params.priv_secret.is_null());
        CStr::from_ptr(&*priv_params.priv_secret)
    };
    let priv_secret = String::from_utf8_lossy(priv_secret_cstr.to_bytes()).to_string();

    let priv_protocol = match priv_params.priv_protocol {
        PrivTypeArgs::Des => Some(k0hax_snmpv3::params::Params::DES_ENCRYPTION.to_string()),
        PrivTypeArgs::Aes128 => Some(k0hax_snmpv3::params::Params::AES128_ENCRYPTION.to_string()),
        PrivTypeArgs::NoPriv => None,
    };
    /* End Priv */

    let cmd = unsafe {
        assert!(!params.cmd.is_null());
        &*params.cmd
    };

    let real_cmd: k0hax_snmpv3::params::Command = match cmd {
        Command::Get { oid: x } => {
            assert!(!x.is_null());
            let oid = unsafe { &**x };
            let oid_cstr = unsafe {
                assert!(!oid.oid.is_null());
                CStr::from_ptr(&*oid.oid)
            };
            let oid_oid = String::from_utf8_lossy(oid_cstr.to_bytes());

            let oid_name_cstr = unsafe {
                assert!(!oid.name.is_null());
                CStr::from_ptr(&*oid.name)
            };
            let oid_name = String::from_utf8_lossy(oid_name_cstr.to_bytes());

            let real_oid: k0hax_snmpv3::oids::OID = k0hax_snmpv3::oids::OID {
                oid: oid_oid.to_string(),
                name: oid_name.to_string(),
            };
            oid_vec.push(real_oid);
            k0hax_snmpv3::params::Command::Get { oids: oid_vec }
        }
        Command::GetNext { oids: x } => {
            assert!(!x.is_null());
            let oid = unsafe { &**x };
            let oid_cstr = unsafe {
                assert!(!oid.oid.is_null());
                CStr::from_ptr(&*oid.oid)
            };
            let oid_oid = String::from_utf8_lossy(oid_cstr.to_bytes());

            let oid_name_cstr = unsafe {
                assert!(!oid.name.is_null());
                CStr::from_ptr(&*oid.name)
            };
            let oid_name = String::from_utf8_lossy(oid_name_cstr.to_bytes());

            let real_oid: k0hax_snmpv3::oids::OID = k0hax_snmpv3::oids::OID {
                oid: oid_oid.to_string(),
                name: oid_name.to_string(),
            };
            oid_vec.push(real_oid);
            k0hax_snmpv3::params::Command::GetNext { oids: oid_vec }
        }
        Command::Walk { oid: x } => {
            assert!(!x.is_null());
            let oid = unsafe { &**x };
            let oid_cstr = unsafe {
                assert!(!oid.oid.is_null());
                CStr::from_ptr(&*oid.oid)
            };
            let oid_oid = String::from_utf8_lossy(oid_cstr.to_bytes());

            let oid_name_cstr = unsafe {
                assert!(!oid.name.is_null());
                CStr::from_ptr(&*oid.name)
            };
            let oid_name = String::from_utf8_lossy(oid_name_cstr.to_bytes());

            let real_oid: k0hax_snmpv3::oids::OID = k0hax_snmpv3::oids::OID {
                oid: oid_oid.to_string(),
                name: oid_name.to_string(),
            };
            k0hax_snmpv3::params::Command::Walk { oid: real_oid }
        }
    };

    let real_params = k0hax_snmpv3::params::Params {
        user: user,
        host: hostname,
        auth: Some(auth_secret),
        auth_protocol: auth_protocol,
        privacy: Some(priv_secret),
        privacy_protocol: priv_protocol,
        cmd: real_cmd,
    };
    let retval = k0hax_snmpv3::run(k0hax_oid_map.clone(), real_params);
    let mut vec_results: Vec<*mut SnmpResult> = Vec::new();
    for t_result in retval.unwrap() {
        let t_raw_result: *mut SnmpResult = Box::into_raw(Box::new(to_c_snmp_result(t_result)));
        vec_results.push(t_raw_result);
    }
    vec_results.shrink_to_fit();
    let (vec_results_ptr, vec_results_len, vec_results_cap) = vec_results.into_raw_parts();
    let retval_results: SnmpResults = SnmpResults {
        length: vec_results_len,
        capacity: vec_results_cap,
        results: vec_results_ptr,
    };
    Box::into_raw(Box::new(retval_results)) as *mut SnmpResults
}

/*
#[no_mangle]
pub unsafe extern "C" fn get_results(oid_map: OidMap, params: Params) -> Result<Vec<SnmpResult>, ()> {
    Err(())
}
*/
