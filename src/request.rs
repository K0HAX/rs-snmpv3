use std::collections::HashMap;
use std::str::FromStr;

use crate::oids;
use crate::oids::{FindOidName, OID};
use crate::{msg_factory, params, Client, Session, Step};

use anyhow::{format_err, Result};
use snmp_mp::{ObjectIdent, PduType, SnmpMsg, VarBind, VarValue};
use snmp_usm::{Digest, PrivKey};

const MIB2_BASE_OID: [u64; 6] = [1, 3, 6, 1, 2, 1];

/**
 * This function retrieves an SNMP response using `get` and prints the result.
*/
pub fn snmp_get<D, P, S>(
    pdu_type: PduType,
    oids: Vec<OID>,
    client: &mut Client,
    session: &mut Session<D, P, S>,
) -> Result<Vec<params::SnmpResult>>
where
    D: Digest,
    P: PrivKey<Salt = S>,
    S: Step + Copy,
{
    let oid_map: HashMap<String, &OID> = oids.iter().map(|x| (x.oid.clone(), x)).collect();
    let oid_list: Vec<String> = oids.iter().map(|x| x.oid.to_string()).collect();
    let var_binds = strings_to_var_binds(oid_list.iter());
    if var_binds.is_empty() {
        return Err(format_err!("invalid OID(s) supplied"));
    }

    let mut get_request = msg_factory::create_request_msg(pdu_type, var_binds, session);

    let mut retval: Vec<params::SnmpResult> = Vec::new();
    let response = client.send_request(&mut get_request, session)?;
    if let Some(var_binds) = get_var_binds(&response) {
        for var_bind in var_binds {
            let vb_string = var_bind.name().to_string();
            let this_oid = vb_string.as_str();
            let oid_obj: OID = match oid_map.get(this_oid) {
                Some(&&ref x) => x.clone(),
                _ => return Err(format_err!("OID not in oid_map: {:#?}", oid_map)),
            };
            let this_result: params::SnmpResult = var_bind_to_snmp_result(
                client.socket.peer_addr()?.to_string(),
                oid_obj.name,
                var_bind.clone(),
            )?;
            retval.push(this_result);
        }
    }

    Ok(retval)
}

pub fn snmp_walk<D, P, S>(
    oid_map: oids::OidMap,
    oid: OID,
    client: &mut Client,
    session: &mut Session<D, P, S>,
) -> Result<Vec<params::SnmpResult>>
where
    D: Digest,
    P: PrivKey<Salt = S>,
    S: Step + Copy,
{
    //println!("== entered snmp_walk ==");
    let oid_list: Option<String> = Some(oid.oid.to_string());
    let mut var_bind = strings_to_var_binds(oid_list.iter());

    if var_bind.is_empty() {
        eprintln!("invalid OID supplied, using default OID\n");
    }

    if var_bind.is_empty() {
        let base_oid = ObjectIdent::from_slice(&MIB2_BASE_OID);
        var_bind = vec![VarBind::new(base_oid)];
    }

    let mut retval: Vec<params::SnmpResult> = Vec::new();
    let end_oid = &next_sibling(var_bind[0].name());
    loop {
        let mut get_next_request =
            msg_factory::create_request_msg(PduType::GetNextRequest, var_bind, session);

        let get_next_response = client.send_request(&mut get_next_request, session)?;

        match get_first_var_bind(&get_next_response) {
            Some(var) => {
                //println!("Found Some(var)");
                if var.name() >= end_oid || var.value() == &VarValue::EndOfMibView {
                    //println!("== exited snmp_walk (EndOfMibView) ==");
                    return Ok(retval);
                }

                let oid_string: &String = &var.name().to_string();
                let oid_obj: OID = OID {
                    name: var.name().to_string(),
                    oid: (*oid_string.clone()).to_string(),
                };
                let this_result: params::SnmpResult = var_bind_to_snmp_result(
                    client.socket.peer_addr()?.to_string(),
                    oid_map
                        .clone()
                        .find_oid_name(oid_obj.oid.clone())
                        .unwrap_or_else(|| oid_obj.oid.to_string()),
                    var.clone(),
                )?;
                //println!("request.rs: {:?}", this_result);
                retval.push(this_result);
                var_bind = vec![VarBind::new(var.name().clone())];
            }

            None => {
                //println!("== exited snmp_walk (None) ==");
                return Ok(retval);
            }
        }
    }
}

fn strings_to_var_binds<'a, I>(strings: I) -> Vec<VarBind>
where
    I: for<'b> Iterator<Item = &'a String>,
{
    strings
        .map(|oid_str| ObjectIdent::from_str(&oid_str))
        .filter_map(Result::ok)
        .map(VarBind::new)
        .collect()
}

fn get_var_binds(msg: &SnmpMsg) -> Option<&[VarBind]> {
    Some(msg.scoped_pdu_data.plaintext()?.var_binds())
}

fn get_first_var_bind(msg: &SnmpMsg) -> Option<&VarBind> {
    get_var_binds(msg)?.first()
}

fn next_sibling(oid: &ObjectIdent) -> ObjectIdent {
    let mut components = oid.components().to_vec();
    let len = components.len();
    components[len - 1] = components[len - 1].wrapping_add(1);

    ObjectIdent::new(components)
}

fn var_bind_to_snmp_result(
    req_host: String,
    req_oid: String,
    req_var_bind: VarBind,
) -> Result<params::SnmpResult> {
    let bound_value: params::SnmpValue = params::SnmpValue::from(req_var_bind.value().to_owned());
    let retval: params::SnmpResult = params::SnmpResult {
        host: req_host,
        oid: req_oid.to_string(),
        result: Some(bound_value),
    };
    Ok(retval)
}
