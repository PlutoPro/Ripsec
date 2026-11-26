//! IKEv2 wire format (RFC 7296). Every length coming off the network is checked.

pub const HEADER_LEN: usize = 28;

pub mod exchange {
    pub const SA_INIT: u8 = 34;
    pub const AUTH: u8 = 35;
    pub const CREATE_CHILD_SA: u8 = 36;
    pub const INFORMATIONAL: u8 = 37;
    pub const INTERMEDIATE: u8 = 43;
    pub const FOLLOWUP_KE: u8 = 44;
}

pub mod flag {
    pub const INITIATOR: u8 = 0x08;
    pub const RESPONSE: u8 = 0x20;
}

pub mod payload {
    pub const SA: u8 = 33;
    pub const KE: u8 = 34;
    pub const IDI: u8 = 35;
    pub const IDR: u8 = 36;
    pub const AUTH: u8 = 39;
    pub const NONCE: u8 = 40;
    pub const NOTIFY: u8 = 41;
    pub const DELETE: u8 = 42;
    pub const TSI: u8 = 44;
    pub const TSR: u8 = 45;
    pub const SK: u8 = 46;
    pub const CP: u8 = 47;
    pub const EAP: u8 = 48;
    pub const SKF: u8 = 53;
}

pub mod notify {
    pub const UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;
    pub const INVALID_SYNTAX: u16 = 7;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const INVALID_KE_PAYLOAD: u16 = 17;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    pub const INTERNAL_ADDRESS_FAILURE: u16 = 36;
    pub const TS_UNACCEPTABLE: u16 = 38;
    pub const TEMPORARY_FAILURE: u16 = 43;
    pub const CHILD_SA_NOT_FOUND: u16 = 44;
    pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
    pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;
    pub const COOKIE: u16 = 16390;
    pub const REKEY_SA: u16 = 16393;
    pub const FRAGMENTATION_SUPPORTED: u16 = 16430;
    pub const INTERMEDIATE_EXCHANGE_SUPPORTED: u16 = 16438;
    pub const ADDITIONAL_KEY_EXCHANGE: u16 = 16441;
}

pub const PROTO_IKE: u8 = 1;
pub const PROTO_ESP: u8 = 3;

pub fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

pub fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

pub fn be64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub spi_i: u64,
    pub spi_r: u64,
    pub next: u8,
    pub exchange: u8,
    pub flags: u8,
    pub msg_id: u32,
}

impl Header {
    /// Parses the header and requires the length field to match the datagram.
    pub fn parse(b: &[u8]) -> Option<Header> {
        if b.len() < HEADER_LEN || b[17] >> 4 != 2 || be32(b, 24)? as usize != b.len() {
            return None;
        }
        Some(Header {
            spi_i: be64(b, 0)?,
            spi_r: be64(b, 8)?,
            next: b[16],
            exchange: b[18],
            flags: b[19],
            msg_id: be32(b, 20)?,
        })
    }

    pub fn encode(&self, total_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&self.spi_i.to_be_bytes());
        out.extend_from_slice(&self.spi_r.to_be_bytes());
        out.extend_from_slice(&[self.next, 0x20, self.exchange, self.flags]);
        out.extend_from_slice(&self.msg_id.to_be_bytes());
        out.extend_from_slice(&(total_len as u32).to_be_bytes());
        out
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Payload<'a> {
    pub kind: u8,
    pub body: &'a [u8],
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    Syntax,
    UnsupportedCritical(u8),
}

pub fn parse_payloads(mut kind: u8, mut data: &[u8]) -> Result<Vec<Payload<'_>>, ParseError> {
    let mut out = Vec::new();
    while kind != 0 {
        if data.len() < 4 || out.len() >= 64 {
            return Err(ParseError::Syntax);
        }
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if len < 4 || len > data.len() {
            return Err(ParseError::Syntax);
        }
        if data[1] & 0x80 != 0 && !(33..=48).contains(&kind) {
            return Err(ParseError::UnsupportedCritical(kind));
        }
        out.push(Payload { kind, body: &data[4..len] });
        kind = data[0];
        data = &data[len..];
    }
    if data.is_empty() { Ok(out) } else { Err(ParseError::Syntax) }
}

pub fn find<'a>(payloads: &[Payload<'a>], kind: u8) -> Option<&'a [u8]> {
    payloads.iter().find(|p| p.kind == kind).map(|p| p.body)
}

/// Builds a payload chain, patching each "next payload" field as it goes.
#[derive(Default)]
pub struct Chain {
    pub first: u8,
    pub bytes: Vec<u8>,
    last_next: Option<usize>,
}

impl Chain {
    pub fn push(&mut self, kind: u8, body: &[u8]) {
        match self.last_next {
            Some(i) => self.bytes[i] = kind,
            None => self.first = kind,
        }
        self.last_next = Some(self.bytes.len());
        self.bytes.extend_from_slice(&[0, 0]);
        self.bytes.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        self.bytes.extend_from_slice(body);
    }

    pub fn notify(&mut self, kind: u16, data: &[u8]) {
        let mut body = vec![0, 0];
        body.extend_from_slice(&kind.to_be_bytes());
        body.extend_from_slice(data);
        self.push(payload::NOTIFY, &body);
    }
}

pub struct Notify<'a> {
    pub protocol: u8,
    pub kind: u16,
    pub spi: &'a [u8],
    pub data: &'a [u8],
}

pub fn notifies<'a>(payloads: &[Payload<'a>]) -> impl Iterator<Item = Notify<'a>> {
    payloads.iter().filter(|p| p.kind == payload::NOTIFY).filter_map(|p| {
        let b = p.body;
        let spi_len = *b.get(1)? as usize;
        Some(Notify {
            protocol: b[0],
            kind: be16(b, 2)?,
            spi: b.get(4..4 + spi_len)?,
            data: b.get(4 + spi_len..)?,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_round_trips() {
        let mut c = Chain::default();
        c.push(payload::NONCE, b"abc");
        c.notify(notify::COOKIE, b"xy");
        let parsed = parse_payloads(c.first, &c.bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].body, b"abc");
        let n = notifies(&parsed).next().unwrap();
        assert_eq!((n.kind, n.data), (notify::COOKIE, &b"xy"[..]));
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(parse_payloads(40, &[0, 0, 0, 3]).is_err());
        assert!(parse_payloads(40, &[0, 0, 0, 9, 1]).is_err());
        assert!(parse_payloads(200, &[0, 0x80, 0, 4]).is_err());
        assert!(Header::parse(&[0; 27]).is_none());
    }
}
