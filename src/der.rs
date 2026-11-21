//! ASN.1 DER, in the `rrl-crypto` crate.
//!
//! The implementation lives there because it is what decides the octets a checksum or a signature
//! covers: a length written non-minimally changes what the KDC hashes, and no other implementation
//! will agree. That makes it part of "what exactly was signed", not a formatting detail — the same
//! question a certificate and a CMS envelope ask — so one encoder answers it for all of them.
//!
//! Re-exported rather than wrapped so that `der::SEQUENCE`, `der::Reader` and `Fields` keep
//! resolving here, and so that a `DerError` raised on one side is the same type the other side
//! matches on. A wrapper would be a second place to forget a function.

pub use rrl_crypto::der::*;
