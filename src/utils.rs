use serde::Deserialize;
use serde_json;

use crate::oids;
use crate::params;

pub fn oidmap_json_read<'a, A>(input: &'a str) -> Result<oids::OidMap<'a>, serde_json::Error>
where
    A: for<'de> DeserializeBorrowed<'de>,
{
    {
        Ok(serde_json::from_str(input)?)
    }
}

pub fn params_json_read<'a, A>(input: &'a str) -> Result<Vec<params::Params<'a>>, serde_json::Error>
where
    A: for<'de> DeserializeBorrowed<'de>,
{
    {
        Ok(serde_json::from_str(input)?)
    }
}

pub trait DeserializeBorrowed<'de> {
    type Deserialize: Deserialize<'de>;
}

pub enum DeserializeBorrowedOidMap {}
pub enum DeserializeBorrowedParams {}

impl<'de> DeserializeBorrowed<'de> for DeserializeBorrowedOidMap {
    type Deserialize = oids::OidMap<'de>;
}

impl<'de> DeserializeBorrowed<'de> for DeserializeBorrowedParams {
    type Deserialize = params::Params<'de>;
}
