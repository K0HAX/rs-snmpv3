use k0hax_snmpv3;
//use std::ffi;
use std::ffi::{c_char, c_void, CStr, CString};
use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum AuthTypeArgs {
    Md5Digest,
    Sha1Digest,
    NoAuth,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum PrivTypeArgs {
    Des,
    Aes128,
    NoPriv,
}

#[derive(Debug, Clone)]
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

/// The struct that we pass back to C with "real" Auth values.
#[derive(Debug)]
#[repr(C)]
pub struct AuthParams {
    auth_protocol: AuthTypeArgs,
    auth_secret: *const c_char,
}

/// The struct that we pass back to C with "real" Priv values.
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
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct SnmpResult {
    pub host: *mut c_char,
    pub oid: *mut c_char,
    pub result: *mut SnmpValue,
}

/// This enum is so that C can identify the type of each `SnmpValue`.
#[repr(C)]
pub enum SnmpValue {
    Int(i32),
    String(*mut c_char),
    //ObjectId(ObjectIdentifier),
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
#[no_mangle]
pub unsafe extern "C" fn new_oid_map() -> *mut c_void {
    let oid_map: OidMap = OidMap { oids: Vec::new() };
    Box::into_raw(Box::new(oid_map)) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn insert_oid_map(oid_ptr: *mut OID, ptr: *mut c_void) {
    assert!(!ptr.is_null());
    assert!(!oid_ptr.is_null());
    let oid_map_ptr = ptr as *mut OidMap;
    let oid_map: &mut OidMap = unsafe { &mut *oid_map_ptr };
    //let mut oid_map: OidMap = *Box::from_raw(&mut ptr as *mut OidMap);
    let oid: &OID = unsafe { &*oid_ptr };
    oid_map.oids.push(*oid);
}

#[no_mangle]
pub unsafe extern "C" fn print_oid_map(ptr: *mut c_void) {
    assert!(!ptr.is_null());
    let oid_map_ptr = ptr as *mut OidMap;
    let oid_map: &OidMap = unsafe { &*oid_map_ptr };
    //let mut oid_map: *mut OidMap = unsafe { &*ptr as *mut OidMap };
    println!("{:#?}", oid_map);
}

#[no_mangle]
pub unsafe extern "C" fn free_oid_map(ptr: *mut c_void) {
    assert!(!ptr.is_null());
    let _ = Box::from_raw(ptr as *mut OidMap);
}
/* End OidMap */

/* Begin Command */
#[no_mangle]
pub unsafe extern "C" fn print_command(ptr: *mut Command) {
    assert!(!ptr.is_null());
    let cmd_ptr = &*ptr;
    println!("{:?}", &cmd_ptr);
}
/* End Command */

/* Begin Auth */
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
#[no_mangle]
pub unsafe extern "C" fn print_params(ptr: *mut Params) {
    let param_ptr = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };
    println!("{:?}", param_ptr);
}
/* End Params */

fn oid_from_strings(oid_str: String, oid_name: String) -> k0hax_snmpv3::oids::OID {
    k0hax_snmpv3::oids::OID {
        oid: oid_str,
        name: oid_name,
    }
}

fn to_c_snmp_result(item: k0hax_snmpv3::params::SnmpResult) -> SnmpResult {
    let host = CString::new(item.host).unwrap();
    let oid = CString::new(item.oid).unwrap();
    let result_intermediate = match item.result {
        Some(x) => x,
        None => panic!("No SnmpValue in SnmpResult!"),
    };
    let result = match result_intermediate {
        k0hax_snmpv3::params::SnmpValue::Int(x) => SnmpValue::Int(x),
        k0hax_snmpv3::params::SnmpValue::String(x) => {
            SnmpValue::String(CString::new(x).unwrap().into_raw())
        }
        k0hax_snmpv3::params::SnmpValue::ObjectId(_) => todo!(),
        k0hax_snmpv3::params::SnmpValue::IpAddress(x) => SnmpValue::IpAddress(x),
        k0hax_snmpv3::params::SnmpValue::Counter(x) => SnmpValue::Counter(x),
        k0hax_snmpv3::params::SnmpValue::UnsignedInt(x) => SnmpValue::UnsignedInt(x),
        k0hax_snmpv3::params::SnmpValue::TimeTicks(x) => SnmpValue::TimeTicks(x),
        k0hax_snmpv3::params::SnmpValue::Opaque(x) => SnmpValue::Opaque(Box::new(x)),
        k0hax_snmpv3::params::SnmpValue::BigCounter(x) => SnmpValue::BigCounter(x),
        k0hax_snmpv3::params::SnmpValue::Unspecified => SnmpValue::Unspecified,
        k0hax_snmpv3::params::SnmpValue::NoSuchObject => SnmpValue::NoSuchObject,
        k0hax_snmpv3::params::SnmpValue::NoSuchInstance => SnmpValue::NoSuchInstance,
        k0hax_snmpv3::params::SnmpValue::EndOfMibView => SnmpValue::EndOfMibView,
    };
    let boxed_result = Box::new(result);
    SnmpResult {
        host: host.into_raw(),
        oid: oid.into_raw(),
        result: Box::into_raw(boxed_result) as *mut SnmpValue,
    }
}

fn free_cstring(item: *mut c_char) {
    let _ = unsafe {
        let _ = CString::from_raw(item);
    };
}

#[no_mangle]
pub unsafe extern "C" fn free_snmp_result(ptr: *mut SnmpResult) {
    assert!(!ptr.is_null());
    let result = Box::from_raw(ptr);
    free_cstring(result.host);
    free_cstring(result.oid);
    let inner_result = Box::from_raw(result.result);
    match *inner_result {
        SnmpValue::String(x) => free_cstring(x),
        _ => (),
    };
}

#[no_mangle]
pub unsafe extern "C" fn run(oid_map_ptr: *mut c_void, param_ptr: *mut Params) -> *mut SnmpResult {
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
    //let retval: k0hax_snmpv3::Params::SnmpResult = k0hax_snmpv3::run
    Box::into_raw(Box::new(to_c_snmp_result(retval.unwrap()[0].clone()))) as *mut SnmpResult
}

/*
#[no_mangle]
pub unsafe extern "C" fn get_results(oid_map: OidMap, params: Params) -> Result<Vec<SnmpResult>, ()> {
    Err(())
}
*/
