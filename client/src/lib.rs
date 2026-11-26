//! The Ripsec VPN client: an IKEv2 initiator with ESP done in user space over UDP, so that
//! it needs nothing from the operating system but a virtual network interface.

/// Network ranges, for programs that build a profile's options.
pub use ripsec_proto::net as cidr;
pub mod connection;
pub mod esp;
pub mod ike;
pub mod ipc;
pub mod profile;
pub mod tun;
pub mod tunnel;
