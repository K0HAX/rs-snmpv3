use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub trait FindOidName {
    fn find_oid_name<'a>(self, input: &'a str) -> Option<String>;
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct OID<'a> {
    pub oid: &'a str,
    pub name: &'a str,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OidMap<'a> {
    #[serde(borrow)]
    pub oids: Vec<OID<'a>>,
}

impl FindOidName for OidMap<'_> {
    fn find_oid_name(self, input: &str) -> Option<String> {
        let oid_map: HashMap<&str, &str> = self.oids.iter().map(|x| (x.oid, x.name)).collect();
        let input_parts: Vec<&str> = input.split(".").collect();
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
