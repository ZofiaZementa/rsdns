use super::{domain::Domain, rr, DNSItem};
use nom::{
    bits::complete as bitsc, combinator::verify, error::Error, number::complete::be_u16,
    sequence::tuple, IResult,
};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

#[derive(ToPrimitive, FromPrimitive, Copy, Clone, Debug)]
pub enum Opcode {
    QUERY = 0,
    STATUS = 2,
    NOTIFY = 4,
    UPDATE = 5,
}

#[derive(ToPrimitive, FromPrimitive, Copy, Clone, Debug)]
pub enum RCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

#[derive(Debug)]
pub struct Header {
    id: u16,
    qr: bool,
    opcode: Opcode,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    rcode: RCode,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DNSItem for Header {
    fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let p_opcode = verify(bitsc::take(4usize), |oc| *oc <= 2);
        let p_rcode = verify(bitsc::take(4usize), |rc| *rc <= 5);
        let second_line = nom::bits::bits::<_, _, Error<(&[u8], usize)>, _, _>(tuple((
            bitsc::take(1usize),
            p_opcode,
            bitsc::take(1usize),
            bitsc::take(1usize),
            bitsc::take(1usize),
            bitsc::take(1usize),
            bitsc::tag(0u8, 3usize),
            p_rcode,
        )));
        tuple((be_u16, second_line, be_u16, be_u16, be_u16, be_u16))(bytes).map(
            |(
                n,
                (id, (qr, opcode, aa, tc, rd, ra, _, rcode), qdcount, ancount, nscount, arcount),
            ): (_, (_, (u8, _, u8, u8, u8, u8, u8, _), _, _, _, _))| {
                (
                    n,
                    Header {
                        id,
                        qr: qr != 0,
                        opcode: FromPrimitive::from_u8(opcode).unwrap(),
                        aa: aa != 0,
                        tc: tc != 0,
                        rd: rd != 0,
                        ra: ra != 0,
                        rcode: FromPrimitive::from_u8(rcode).unwrap(),
                        qdcount,
                        ancount,
                        nscount,
                        arcount,
                    },
                )
            },
        )
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len_bytes());
        let second_line_first_byte = ((self.qr as u8) << 7)
            & (((self.opcode.to_u8().unwrap()) << 3) & 0x78)
            & ((self.aa as u8) << 2)
            & ((self.tc as u8) << 1)
            & (self.rd as u8);
        let second_line_second_byte =
            ((self.ra as u8) << 7) & ((self.rcode.to_u8().unwrap()) & 0x0F);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.push(second_line_first_byte);
        out.push(second_line_second_byte);
        out.extend_from_slice(&self.qdcount.to_be_bytes());
        out.extend_from_slice(&self.ancount.to_be_bytes());
        out.extend_from_slice(&self.nscount.to_be_bytes());
        out.extend_from_slice(&self.arcount.to_be_bytes());
        out
    }

    fn len_bytes(&self) -> usize {
        12
    }
}

#[repr(u16)]
#[derive(ToPrimitive, FromPrimitive, Copy, Clone, Debug)]
pub enum QTypeVal {
    AXFR = 252,
    MAILB = 253,
    ALL = 255,
}

#[derive(Copy, Clone, Debug)]
pub enum QType {
    Type(rr::Type),
    QType(QTypeVal),
}

impl FromPrimitive for QType {
    fn from_u64(n: u64) -> Option<Self> {
        if n <= u16::MAX.into() {
            if n <= 255 && n >= 252 {
                Some(QType::QType(FromPrimitive::from_u64(n)?))
            } else {
                Some(QType::Type(FromPrimitive::from_u64(n)?))
            }
        } else {
            None
        }
    }

    fn from_i64(n: i64) -> Option<Self> {
        if n > 0 {
            Self::from_u64(n as u64)
        } else {
            None
        }
    }
}

impl ToPrimitive for QType {
    fn to_i64(&self) -> Option<i64> {
        match self {
            QType::QType(t) => t.to_i64(),
            QType::Type(t) => t.to_i64(),
        }
    }

    fn to_u64(&self) -> Option<u64> {
        self.to_i64().map(|n| n as u64)
    }
}

#[repr(u16)]
#[derive(ToPrimitive, FromPrimitive, Copy, Clone, Debug)]
pub enum QClassVal {
    ALL = 255,
}

#[derive(Copy, Clone, Debug)]
pub enum QClass {
    Class(rr::Class),
    QClass(QClassVal),
}

impl FromPrimitive for QClass {
    fn from_u64(n: u64) -> Option<Self> {
        if n <= u16::MAX.into() {
            if n == 255 {
                Some(QClass::QClass(FromPrimitive::from_u64(n)?))
            } else {
                Some(QClass::Class(FromPrimitive::from_u64(n)?))
            }
        } else {
            None
        }
    }

    fn from_i64(n: i64) -> Option<Self> {
        if n >= 0 {
            Self::from_u64(n as u64)
        } else {
            None
        }
    }
}

impl ToPrimitive for QClass {
    fn to_i64(&self) -> Option<i64> {
        match self {
            QClass::QClass(c) => c.to_i64(),
            QClass::Class(c) => c.to_i64(),
        }
    }

    fn to_u64(&self) -> Option<u64> {
        self.to_i64().map(|n| n as u64)
    }
}

#[derive(Debug)]
pub struct Question {
    qname: Domain,
    qtype: QType,
    qclass: QClass,
}

impl DNSItem for Question {
    fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        tuple((Domain::parse, be_u16, be_u16))(bytes).map(|(n, (qname, qtype, qclass))| {
            (
                n,
                Question {
                    qname,
                    qtype: FromPrimitive::from_u16(qtype).unwrap(),
                    qclass: FromPrimitive::from_u16(qclass).unwrap(),
                },
            )
        })
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len_bytes());
        out.append(&mut self.qname.as_bytes());
        out.extend_from_slice(&self.qtype.to_u16().unwrap().to_be_bytes());
        out.extend_from_slice(&self.qclass.to_u16().unwrap().to_be_bytes());
        out
    }

    fn len_bytes(&self) -> usize {
        self.qname.len_bytes() + 4
    }
}

pub struct Message {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<rr::RR>,
    authorities: Vec<rr::RR>,
    additionals: Vec<rr::RR>,
}
