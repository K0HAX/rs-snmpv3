extern crate k0hax_snmpv3;
use anyhow::{format_err, Result};
use clap::{Parser, ValueEnum};
use std::fs::File;
use std::io::prelude::*;
use std::process::ExitCode;

use k0hax_snmpv3::{oids, params, utils};

#[allow(dead_code)]
fn write_json(path: &str, data: &Vec<params::Params>) -> Result<()> {
    let mut output = File::create(path)?;
    serde_json::to_writer(&mut output, &data)?;
    Ok(())
}

fn read_json<'a>(path: &'a str, mut buffer: &'a mut String) -> Result<Vec<params::Params<'a>>> {
    let mut f = File::open(path)?;
    f.read_to_string(&mut buffer)?;
    Ok(utils::params_json_read::<utils::DeserializeBorrowedParams>(
        buffer,
    )?)
}

fn read_oid_json<'a>(path: &'a str, mut buffer: &'a mut String) -> Result<oids::OidMap<'a>> {
    let mut f = File::open(path)?;
    f.read_to_string(&mut buffer)?;
    Ok(utils::oidmap_json_read::<utils::DeserializeBorrowedOidMap>(
        buffer,
    )?)
}

#[allow(dead_code)]
fn write_oid_json(path: &str, data: &oids::OidMap) -> Result<()> {
    let mut output = File::create(path)?;
    serde_json::to_writer(&mut output, &data)?;
    Ok(())
}

fn get_all(
    oid_map: oids::OidMap,
    data: Vec<params::Params>,
) -> Result<Vec<(String, Vec<params::SnmpResult>)>> {
    let mut retval: Vec<(String, Vec<params::SnmpResult>)> = Vec::new();

    for item in data {
        retval.push((item.host.clone(), k0hax_snmpv3::run(oid_map.clone(), item)?));
    }

    Ok(retval)
}

#[allow(dead_code)]
fn print_vals(data: &Vec<(String, Vec<params::SnmpResult>)>) -> Result<()> {
    for (key, item) in data {
        println!("Host: {}", key);
        for result in item {
            println!("");
            match &result.result {
                Some(params::SnmpValue::String(x)) => println!("{}: {}", result.oid, x),
                Some(x) => println!("{}: {:?}", result.oid, x),
                None => return Err(format_err!("No SnmpResult Value found!")),
            };
        }
        println!("----");
    }
    Ok(())
}

fn write_json_vals(path: &str, data: Vec<(String, Vec<params::SnmpResult>)>) -> Result<()> {
    let mut output = File::create(path)?;
    serde_json::to_writer(&mut output, &data)?;
    Ok(())
}

#[derive(Parser, Debug)]
/// Simple program to get SNMP values from hosts
///
/// This is a long about test.
#[command(author, version, about)]
struct Cli {
    /// Uses a custom config file
    #[arg(
        short,
        long,
        value_name = "FILE",
        group = "config_mode",
        required = true
    )]
    config: Option<String>,

    /// SNMP Agent IP
    #[arg(long, requires_all=["username", "oid"], group="config_mode", required=true)]
    hostname: Option<String>,

    /// OID to walk
    oid: Option<String>,

    /// SNMP Username
    username: Option<String>,

    /// SNMP Auth Protocol
    #[arg(requires_all=["auth_key"])]
    auth_protocol: Option<AuthTypeArgs>,

    /// SNMP Auth Key
    #[arg(requires_all=["auth_protocol"])]
    auth_key: Option<String>,

    /// SNMP Privacy Protocol
    #[arg(requires_all=["priv_key"])]
    privacy_protocol: Option<PrivTypeArgs>,

    /// SNMP Privacy Key
    #[arg(requires_all=["privacy_protocol"])]
    priv_key: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
enum AuthTypeArgs {
    Md5Digest,
    Sha1Digest,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
enum PrivTypeArgs {
    Des,
    Aes128,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let config = &cli.config;
    let params_buf: &mut String = &mut String::new();
    let oid_arg: String = if let Some(c_oid) = cli.oid {
        c_oid
    } else {
        "".to_string()
    };
    let hostname: Option<String> = cli.hostname;
    let username: Option<String> = cli.username;
    let auth_type: Option<AuthTypeArgs> = cli.auth_protocol;
    let priv_type: Option<PrivTypeArgs> = cli.privacy_protocol;

    let my_params: Vec<params::Params> = if let Some(c) = config {
        read_json(c, params_buf).unwrap()
    } else {
        // Auth and Auth Key
        let real_auth = match auth_type {
            Some(AuthTypeArgs::Md5Digest) => Some(params::Params::MD5_DIGEST.to_string()),
            Some(AuthTypeArgs::Sha1Digest) => Some(params::Params::SHA1_DIGEST.to_string()),
            None => None,
        };

        let auth_key = match cli.auth_key {
            Some(x) => Some(x.to_string()),
            None => None,
        };

        // Priv and Priv Key
        let real_priv = match priv_type {
            Some(PrivTypeArgs::Des) => Some(params::Params::DES_ENCRYPTION.to_string()),
            Some(PrivTypeArgs::Aes128) => Some(params::Params::AES128_ENCRYPTION.to_string()),
            None => None,
        };

        let priv_key = match cli.priv_key {
            Some(x) => Some(x.to_string()),
            None => None,
        };

        // Command `Walk`
        let oid_raw: oids::OID = oids::OID {
            oid: &oid_arg,
            name: &oid_arg,
        };

        let cmd_param: params::Command = params::Command::Walk { oid: oid_raw };

        println!("Auth Type: {:?}", real_auth);
        println!("Auth Key : {:?}", auth_key);
        println!("Priv Type: {:?}", real_priv);
        println!("Priv Key : {:?}", priv_key);
        Vec::from([params::Params {
            user: username.unwrap(),
            host: hostname.unwrap(),
            auth: auth_key,
            auth_protocol: real_auth,
            privacy: priv_key,
            privacy_protocol: real_priv,
            cmd: cmd_param,
        }])
    };

    let oids_buf: &mut String = &mut String::new();
    let oids: oids::OidMap = read_oid_json("oids.json", oids_buf).unwrap();

    let data = get_all(oids, my_params).unwrap();

    for data_row in &data {
        println!("=== {} ===", data_row.0);
        for row_result in &data_row.1 {
            println!("{}", row_result);
        }
    }
    write_json_vals("output.json", data).unwrap();

    ExitCode::SUCCESS
}
