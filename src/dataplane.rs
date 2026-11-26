//! What the IKE engine asks of the packet forwarding layer.

use crate::net::Cidr;
use std::io;
use std::net::SocketAddrV4;

/// Linux UDP encapsulation type for ESP (RFC 3948), from linux/udp.h.
pub const UDP_ENCAP_ESPINUDP: u16 = 2;

/// One CHILD SA pair. Key material is the AES key followed by the GCM salt.
#[derive(Clone)]
pub struct Child {
    pub reqid: u32,
    pub local: SocketAddrV4,
    pub peer: SocketAddrV4,
    /// ESP-in-UDP, used when either side is behind NAT.
    pub udp_encap: bool,
    pub spi_in: u32,
    pub spi_out: u32,
    pub key_in: Vec<u8>,
    pub key_out: Vec<u8>,
    pub esn: bool,
    pub local_ts: Vec<Cidr>,
    pub remote_ts: Vec<Cidr>,
}

pub trait Dataplane {
    /// Installs both SAs and the policies for their selectors. Safe to repeat for a rekey.
    fn add(&mut self, child: &Child) -> io::Result<()>;
    /// Removes the SAs, and the policies too when `policies` is set.
    fn remove(&mut self, child: &Child, policies: bool);
    /// Bytes carried inbound and outbound.
    fn bytes(&mut self, child: &Child) -> (u64, u64);
}
