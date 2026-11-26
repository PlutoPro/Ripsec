//! Linux XFRM over netlink: ESP runs entirely in the kernel.

use crate::dataplane::{Child, Dataplane, UDP_ENCAP_ESPINUDP};
use crate::net::Cidr;
use std::io;
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NEWSA: u16 = 0x10;
const DELSA: u16 = 0x11;
const GETSA: u16 = 0x12;
const DELPOLICY: u16 = 0x14;
const UPDPOLICY: u16 = 0x19;
const NLMSG_ERROR: u16 = 2;

const XFRMA_ENCAP: u16 = 4;
const XFRMA_TMPL: u16 = 5;
const XFRMA_ALG_AEAD: u16 = 18;
const XFRMA_REPLAY_ESN_VAL: u16 = 23;

const AF_INET: u16 = 2;
const IPPROTO_ESP: u8 = 50;
const MODE_TUNNEL: u8 = 1;
const STATE_ESN: u8 = 128;
const REPLAY_WINDOW: u32 = 1024;
const DIR_IN: u8 = 0;
const DIR_OUT: u8 = 1;
const DIR_FWD: u8 = 2;

/// Native-endian message builder mirroring the kernel's structure layout.
#[derive(Default)]
struct Buf(Vec<u8>);

impl Buf {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_ne_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_ne_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_ne_bytes());
    }
    fn be16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn be32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn zero(&mut self, n: usize) {
        self.0.resize(self.0.len() + n, 0);
    }
    fn align(&mut self, to: usize) {
        self.0.resize(self.0.len().next_multiple_of(to), 0);
    }
    /// xfrm_address_t
    fn addr(&mut self, v: u32) {
        self.be32(v);
        self.zero(12);
    }
    /// struct xfrm_selector (56 bytes)
    fn selector(&mut self, src: Cidr, dst: Cidr) {
        self.addr(dst.first());
        self.addr(src.first());
        self.zero(8); // ports and masks: any
        self.u16(AF_INET);
        self.u8(dst.prefix);
        self.u8(src.prefix);
        self.zero(4); // proto: any, plus padding
        self.u32(0); // ifindex
        self.u32(0); // user
    }
    /// struct xfrm_lifetime_cfg with no limits, followed by no current usage.
    fn lifetimes(&mut self) {
        (0..4).for_each(|_| self.u64(u64::MAX));
        self.zero(32 + 32);
    }
    fn attr(&mut self, kind: u16, value: &[u8]) {
        self.u16((value.len() + 4) as u16);
        self.u16(kind);
        self.0.extend_from_slice(value);
        self.align(4);
    }
}

fn sa_info(c: &Child, src: SocketAddrV4, dst: SocketAddrV4, spi: u32, key: &[u8]) -> Vec<u8> {
    let any = Cidr::new([0, 0, 0, 0].into(), 0).expect("valid prefix");
    let mut m = Buf::default();
    m.selector(any, any);
    // struct xfrm_id
    m.addr((*dst.ip()).into());
    m.be32(spi);
    m.u8(IPPROTO_ESP);
    m.zero(3);
    m.addr((*src.ip()).into());
    m.lifetimes();
    m.zero(12); // stats
    m.u32(0); // seq
    m.u32(c.reqid);
    m.u16(AF_INET);
    m.u8(MODE_TUNNEL);
    m.u8(0); // replay window is given by the ESN attribute
    m.u8(if c.esn { STATE_ESN } else { 0 });
    m.align(8);

    let mut aead = Buf::default();
    let name = b"rfc4106(gcm(aes))";
    aead.0.extend_from_slice(name);
    aead.zero(64 - name.len());
    aead.u32((key.len() * 8) as u32);
    aead.u32(128); // ICV bits
    aead.0.extend_from_slice(key);
    m.attr(XFRMA_ALG_AEAD, &aead.0);

    let mut replay = Buf::default();
    replay.u32(REPLAY_WINDOW / 32);
    replay.zero(16); // sequence counters
    replay.u32(REPLAY_WINDOW);
    replay.zero(REPLAY_WINDOW as usize / 8);
    m.attr(XFRMA_REPLAY_ESN_VAL, &replay.0);

    if c.udp_encap {
        let mut encap = Buf::default();
        encap.u16(UDP_ENCAP_ESPINUDP);
        encap.be16(src.port());
        encap.be16(dst.port());
        encap.zero(2 + 16);
        m.attr(XFRMA_ENCAP, &encap.0);
    }
    m.0
}

/// struct xfrm_usersa_id
fn sa_id(dst: SocketAddrV4, spi: u32) -> Vec<u8> {
    let mut m = Buf::default();
    m.addr((*dst.ip()).into());
    m.be32(spi);
    m.u16(AF_INET);
    m.u8(IPPROTO_ESP);
    m.align(8);
    m.0
}

fn policy(reqid: u32, src: Cidr, dst: Cidr, dir: u8, tmpl_src: u32, tmpl_dst: u32) -> Vec<u8> {
    let mut m = Buf::default();
    // struct xfrm_userpolicy_info
    m.selector(src, dst);
    m.lifetimes();
    m.u32(2000); // priority
    m.u32(0); // index
    m.u8(dir);
    m.zero(3); // action allow, flags, share any
    m.align(8);
    // struct xfrm_user_tmpl
    let mut t = Buf::default();
    t.addr(tmpl_dst);
    t.be32(0); // any SPI: the kernel uses the newest SA for this reqid
    t.u8(IPPROTO_ESP);
    t.zero(3);
    t.u16(AF_INET);
    t.zero(2);
    t.addr(tmpl_src);
    t.u32(reqid);
    t.u8(MODE_TUNNEL);
    t.zero(3);
    (0..3).for_each(|_| t.u32(u32::MAX));
    m.attr(XFRMA_TMPL, &t.0);
    m.0
}

/// struct xfrm_userpolicy_id
fn policy_id(src: Cidr, dst: Cidr, dir: u8) -> Vec<u8> {
    let mut m = Buf::default();
    m.selector(src, dst);
    m.u32(0);
    m.u8(dir);
    m.align(8);
    m.0
}

pub struct Xfrm {
    socket: OwnedFd,
    seq: u32,
}

impl Xfrm {
    pub fn open() -> io::Result<Xfrm> {
        // SAFETY: socket() has no memory preconditions; the result is checked.
        let fd = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_XFRM)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a freshly created descriptor that nothing else owns.
        Ok(Xfrm { socket: unsafe { OwnedFd::from_raw_fd(fd) }, seq: 0 })
    }

    /// Sends one request and returns the kernel's reply message type and payload.
    fn request(&mut self, kind: u16, flags: u16, body: &[u8]) -> io::Result<(u16, Vec<u8>)> {
        self.seq += 1;
        let mut m = Buf::default();
        m.u32((16 + body.len()) as u32);
        m.u16(kind);
        m.u16(libc::NLM_F_REQUEST as u16 | flags);
        m.u32(self.seq);
        m.u32(0);
        m.0.extend_from_slice(body);
        let fd = self.socket.as_raw_fd();
        // SAFETY: the pointer and length describe the live buffer `m.0`.
        if unsafe { libc::send(fd, m.0.as_ptr().cast(), m.0.len(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut reply = vec![0u8; 8192];
        loop {
            // SAFETY: the kernel writes at most `reply.len()` bytes into `reply`.
            let n = unsafe { libc::recv(fd, reply.as_mut_ptr().cast(), reply.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            if n < 16 || reply[8..12] != self.seq.to_ne_bytes() {
                continue;
            }
            let reply_kind = u16::from_ne_bytes([reply[4], reply[5]]);
            if reply_kind == NLMSG_ERROR && n >= 20 {
                let code = i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]);
                if code != 0 {
                    return Err(io::Error::from_raw_os_error(-code));
                }
            }
            return Ok((reply_kind, reply[16..n].to_vec()));
        }
    }

    fn command(&mut self, kind: u16, body: &[u8]) -> io::Result<()> {
        self.request(kind, libc::NLM_F_ACK as u16, body).map(drop)
    }

    fn sa_bytes(&mut self, dst: SocketAddrV4, spi: u32) -> u64 {
        // curlft.bytes sits after selector, id, source address and lifetime limits.
        const OFFSET: usize = 56 + 24 + 16 + 64;
        match self.request(GETSA, 0, &sa_id(dst, spi)) {
            Ok((NEWSA, body)) => {
                body.get(OFFSET..OFFSET + 8).and_then(|b| b.try_into().ok()).map_or(0, u64::from_ne_bytes)
            }
            _ => 0,
        }
    }
}

fn policies(c: &Child) -> impl Iterator<Item = (Cidr, Cidr, u8, u32, u32)> + '_ {
    let local: u32 = (*c.local.ip()).into();
    let peer: u32 = (*c.peer.ip()).into();
    c.local_ts.iter().flat_map(move |&l| {
        c.remote_ts.iter().flat_map(move |&r| {
            [(l, r, DIR_OUT, local, peer), (r, l, DIR_IN, peer, local), (r, l, DIR_FWD, peer, local)]
        })
    })
}

impl Dataplane for Xfrm {
    fn add(&mut self, c: &Child) -> io::Result<()> {
        let result = (|| {
            self.command(NEWSA, &sa_info(c, c.peer, c.local, c.spi_in, &c.key_in))?;
            self.command(NEWSA, &sa_info(c, c.local, c.peer, c.spi_out, &c.key_out))?;
            for (src, dst, dir, from, to) in policies(c) {
                self.command(UPDPOLICY, &policy(c.reqid, src, dst, dir, from, to))?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.remove(c, false);
        }
        result
    }

    fn remove(&mut self, c: &Child, remove_policies: bool) {
        // Deleting something already gone is not an error worth reporting.
        if remove_policies {
            for (src, dst, dir, ..) in policies(c) {
                let _ = self.command(DELPOLICY, &policy_id(src, dst, dir));
            }
        }
        let _ = self.command(DELSA, &sa_id(c.local, c.spi_in));
        let _ = self.command(DELSA, &sa_id(c.peer, c.spi_out));
    }

    fn bytes(&mut self, c: &Child) -> (u64, u64) {
        (self.sa_bytes(c.local, c.spi_in), self.sa_bytes(c.peer, c.spi_out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structures_have_kernel_sizes() {
        let any: Cidr = "0.0.0.0/0".parse().unwrap();
        let a: SocketAddrV4 = "10.0.0.1:4500".parse().unwrap();
        let mut selector = Buf::default();
        selector.selector(any, any);
        assert_eq!(selector.0.len(), 56);
        assert_eq!(sa_id(a, 1).len(), 24);
        assert_eq!(policy_id(any, any, 0).len(), 64);
        // xfrm_userpolicy_info (168) + attribute header (4) + xfrm_user_tmpl (64)
        assert_eq!(policy(1, any, any, 0, 0, 0).len(), 168 + 4 + 64);
    }
}
