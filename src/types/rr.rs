pub mod cname;

use super::{domain, DNSItem};
use nom::{
    number::complete::{be_i32, be_u16},
    sequence::tuple,
    IResult,
};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::fmt::Debug;

#[repr(u16)]
#[derive(ToPrimitive, FromPrimitive, Copy, Clone, Debug)]
pub enum Type {
    // A = 1,
    // NS = 2,
    CNAME = 4,
    // SOA = 5,
    // PTR = 12,i
    // HINFO = 13,
    // MX = 15,
    // TXT = 16,
    // RP = 17,
    // AFSDB = 18,
    // SIG = 24,
    // KEY = 25,
    // AAAA = 28,
    // LOC = 29,
    // SRV = 33,
    // NAPTR = 35,
    // KX = 36,
    // CERT = 37,
    // DNAME = 39,
    // APL = 42,
    // DS = 43,
    // SSHFP = 44,
    // IPSECKY = 45,
    // RRSIG = 46,
    // NSEC = 47,
    // DNSKEY = 48,
    // DHCID = 49,
    // NSEC3 = 50,
    // NSEC3PARAM = 51,
    // TLSA = 52,
    // SMIMEA = 53,
    // HIP = 55,
    // CDS = 59,
    // CDNSKEY = 60,
    // OPENPGPKEY = 61,
    // CSYNC = 62,
    // ZONEMD = 63,
    // SVCB = 64,
    // HTTPS = 65,
    // EUI48 = 108,
    // EUI64 = 109,
    // TKEY = 249,
    // TSIG = 250,
    // URI = 256,
    // CAA = 257,
    // TA = 32768,
    // DLV = 32769,
}

impl DNSItem for Type {
    fn parse(bytes: &[u8]) -> IResult<&[u8], Type> {
        be_u16(bytes).map(|(next, t)| (next, FromPrimitive::from_u16(t).unwrap()))
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.to_u16().unwrap().to_be_bytes().to_vec()
    }

    fn len_bytes(&self) -> usize {
        2
    }
}

pub struct RData(Box<dyn DNSItem>);

impl RData {
    fn parse<'a>(t: &Type, bytes: &'a [u8]) -> IResult<&'a [u8], RData> {
        let res;
        match t {
            Type::CNAME => res = cname::RData::parse(bytes),
        };
        res.map(|(n, i)| (n, RData(Box::new(i) as Box<dyn DNSItem>)))
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes()
    }

    fn len_bytes(&self) -> usize {
        self.0.len_bytes()
    }
}

#[repr(u16)]
#[derive(ToPrimitive, FromPrimitive, Copy, Clone, Debug)]
pub enum Class {
    IN = 1,
    CH = 3,
    HS = 4,
}

impl DNSItem for Class {
    fn parse(bytes: &[u8]) -> IResult<&[u8], Class> {
        be_u16(bytes).map(|(next, c)| (next, FromPrimitive::from_u16(c).unwrap()))
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.to_u16().unwrap().to_be_bytes().to_vec()
    }

    fn len_bytes(&self) -> usize {
        2
    }
}

pub struct RR {
    pub name: domain::Domain,
    pub rrtype: Type,
    pub class: Class,
    pub ttl: i32,
    pub rdata: RData,
}

impl DNSItem for RR {
    fn parse(bytes: &[u8]) -> IResult<&[u8], RR> {
        let (n, (d, t, c, ttl)) =
            tuple((domain::Domain::parse, Type::parse, Class::parse, be_i32))(bytes)?;
        let rd = |b| RData::parse(&t, b);
        rd(n).map(|(next, rdata)| {
            (
                next,
                RR {
                    name: d,
                    rrtype: t,
                    class: c,
                    ttl,
                    rdata,
                },
            )
        })
    }

    fn as_bytes(&self) -> Vec<u8> {
        let len_total = self.name.len_bytes()
            + self.rrtype.len_bytes()
            + self.class.len_bytes()
            + 4
            + self.rdata.len_bytes();
        let mut out = Vec::with_capacity(len_total);
        out.append(&mut self.name.as_bytes());
        out.append(&mut self.rrtype.as_bytes());
        out.append(&mut self.class.as_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out.append(&mut self.rdata.as_bytes());
        out
    }
}
