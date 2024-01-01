use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub trait FindOidName {
    fn find_oid_name(self, input: String) -> Option<String>;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OID {
    pub oid: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OidMap {
    pub oids: Vec<OID>,
}

impl FindOidName for OidMap {
    fn find_oid_name(self, input: String) -> Option<String> {
        let oid_map: HashMap<String, String> = self
            .oids
            .iter()
            .map(|x| (x.oid.clone(), x.name.clone()))
            .collect();
        let input_parts: Vec<&str> = input.as_str().split(".").collect();
        for i in (0..input_parts.len() + 1).rev() {
            let this_try = input_parts[0..i].join(".");
            match oid_map.get(this_try.as_str()) {
                Some(x) => {
                    let this_val = x.to_string();
                    let remainder = input_parts[i..input_parts.len()].join(".").to_string();
                    if remainder.len() == 0 {
                        return Some(this_val);
                    }
                    let retval = vec![this_val, remainder].join(".");
                    return Some(retval);
                }
                _ => (),
            };
        }
        None
    }
}
