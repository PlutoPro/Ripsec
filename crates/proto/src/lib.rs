//! IKEv2 pieces used by both ends: RFC 7296 with RFC 7383 fragmentation, RFC 9242
//! IKE_INTERMEDIATE and RFC 9370 additional key exchanges carrying ML-KEM.

pub mod crypto;
pub mod net;
pub mod proposal;
pub mod secured;
pub mod wire;
