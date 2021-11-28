use super::DNSItem;
use nom::{
    bytes::complete::tag,
    combinator::verify,
    multi::{length_data, many_till},
    number::complete::be_u8,
    IResult,
};

#[derive(Debug)]
pub struct Subdomain(Vec<u8>);

impl Subdomain {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl DNSItem for Subdomain {
    fn parse(bytes: &[u8]) -> IResult<&[u8], Subdomain> {
        verify(
            verify(length_data(be_u8), |bytes: &[u8]| bytes.len() < 63),
            |bytes: &[u8]| bytes.iter().all(|byte| byte.is_ascii_alphabetic()),
        )(bytes)
        .map(|(next, res)| (next, Subdomain(Vec::from(res))))
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() + 1);
        out.push(self.0.len() as u8);
        out.extend_from_slice(&self.0);
        out
    }

    fn len_bytes(&self) -> usize {
        self.0.len() + 1
    }
}

#[derive(Debug)]
pub struct Domain(Vec<Subdomain>);

impl Domain {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl DNSItem for Domain {
    fn parse(bytes: &[u8]) -> IResult<&[u8], Domain> {
        let before = |b| {
            many_till(Subdomain::parse, tag([0]))(b).map(|(next, (res, _))| (next, Domain(res)))
        };
        verify(before, |domain: &Domain| domain.len_bytes() <= 255)(bytes)
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .flat_map(|sds| sds.as_bytes().to_vec())
            .collect()
    }

    fn len_bytes(&self) -> usize {
        self.0
            .iter()
            .map(Subdomain::len)
            .reduce(std::ops::Add::add)
            .unwrap()
            + self.0.len()
            + 1
    }
}
