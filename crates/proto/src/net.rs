//! IPv4 networks, plus the traffic selector payload that carries address ranges.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cidr {
    base: u32,
    pub prefix: u8,
}

impl Cidr {
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Option<Cidr> {
        (prefix <= 32).then(|| Cidr { base: u32::from(addr) & mask(prefix), prefix })
    }

    pub fn host(addr: Ipv4Addr) -> Cidr {
        Cidr { base: addr.into(), prefix: 32 }
    }

    pub fn addr(&self) -> Ipv4Addr {
        self.base.into()
    }

    pub fn first(&self) -> u32 {
        self.base
    }

    pub fn last(&self) -> u32 {
        self.base | !mask(self.prefix)
    }

    pub fn overlaps(&self, other: &Cidr) -> bool {
        self.first() <= other.last() && other.first() <= self.last()
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix.min(32))) }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Cidr, String> {
        let (addr, prefix) = s.split_once('/').unwrap_or((s, "32"));
        addr.trim()
            .parse()
            .ok()
            .zip(prefix.trim().parse().ok())
            .and_then(|(a, p)| Cidr::new(a, p))
            .ok_or_else(|| format!("invalid IPv4 network: {s}"))
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr(), self.prefix)
    }
}

/// An inclusive address range from a traffic selector.
pub type Range = (u32, u32);

const TS_IPV4: u8 = 7;
const MAX_SELECTORS: usize = 32;

/// Parses a TS payload, keeping only IPv4 selectors for all protocols and ports.
pub fn parse_ts(b: &[u8]) -> Option<Vec<Range>> {
    let count = *b.first()?;
    let mut rest = b.get(4..)?;
    let mut out = Vec::new();
    for _ in 0..count {
        let len = u16::from_be_bytes([*rest.get(2)?, *rest.get(3)?]) as usize;
        if len < 8 || len > rest.len() {
            return None;
        }
        let s = &rest[..len];
        if s[0] == TS_IPV4 && len == 16 && s[1] == 0 && s[4..8] == [0, 0, 0xff, 0xff] {
            out.push((
                u32::from_be_bytes(s[8..12].try_into().ok()?),
                u32::from_be_bytes(s[12..16].try_into().ok()?),
            ));
        }
        rest = &rest[len..];
    }
    Some(out)
}

pub fn encode_ts(nets: &[Cidr]) -> Vec<u8> {
    let mut out = vec![nets.len() as u8, 0, 0, 0];
    for n in nets {
        out.extend_from_slice(&[TS_IPV4, 0, 0, 16, 0, 0, 0xff, 0xff]);
        out.extend_from_slice(&n.first().to_be_bytes());
        out.extend_from_slice(&n.last().to_be_bytes());
    }
    out
}

/// Intersects proposed ranges with the networks we allow, as a list of CIDR blocks.
pub fn narrow(proposed: &[Range], allowed: &[Cidr]) -> Vec<Cidr> {
    let mut out: Vec<Cidr> = Vec::new();
    for &(start, end) in proposed {
        for net in allowed {
            let mut lo = u64::from(start.max(net.first()));
            let hi = u64::from(end.min(net.last()));
            // Cover [lo, hi] with the largest aligned blocks that fit.
            while lo <= hi && out.len() < MAX_SELECTORS {
                let align = if lo == 0 { 32 } else { lo.trailing_zeros().min(32) };
                let fit = (hi - lo + 1).ilog2();
                let bits = align.min(fit);
                let block = Cidr { base: lo as u32, prefix: (32 - bits) as u8 };
                if !out.contains(&block) {
                    out.push(block);
                }
                lo += 1u64 << bits;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    #[test]
    fn narrows_to_allowed() {
        assert_eq!(narrow(&[(0, u32::MAX)], &[c("10.1.0.0/16")]), vec![c("10.1.0.0/16")]);
        assert_eq!(narrow(&[(0, u32::MAX)], &[c("0.0.0.0/0")]), vec![c("0.0.0.0/0")]);
        assert!(narrow(&[(c("10.2.0.0").first(), c("10.2.0.0").first())], &[c("10.1.0.0/16")]).is_empty());
        let r = (c("10.0.0.1").first(), c("10.0.0.4").first());
        assert_eq!(narrow(&[r], &[c("10.0.0.0/24")]), vec![c("10.0.0.1"), c("10.0.0.2/31"), c("10.0.0.4")]);
    }

    #[test]
    fn ts_round_trips() {
        let nets = [c("192.168.1.0/24")];
        assert_eq!(parse_ts(&encode_ts(&nets)).unwrap(), vec![(nets[0].first(), nets[0].last())]);
        assert!(parse_ts(&[1, 0, 0, 0, 7, 0, 0, 99]).is_none());
    }
}
