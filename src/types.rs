pub mod domain;
pub mod message;
pub mod rr;

use crate::util::{nom_debug_err, nom_remainder_err};
use anyhow::Result;
use nom::{Finish, IResult};

pub trait DNSItem {
    fn parse(bytes: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized;

    fn as_bytes(&self) -> Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        nom_remainder_err!(nom_debug_err!(Self::parse(bytes).finish())?)
    }

    fn len_bytes(&self) -> usize {
        self.as_bytes().len()
    }
}

//TODO Derive macro for DNSItem
