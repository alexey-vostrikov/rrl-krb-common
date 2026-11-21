//! Time spellings for ASN.1, in the `rrl-crypto` crate.
//!
//! Moved with `der`: a `GeneralizedTime` is part of the octets a signature covers, so it belongs
//! beside the encoder rather than beside the messages that carry it.

pub use rrl_crypto::time::*;
