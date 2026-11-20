//! ASN.1 DER, re-exported from the crypto layer.
//!
//! The implementation lives in `rrl-crypto` (RRL-7.8): every crate of this family that speaks DER
//! speaks it for the same reason - to cover octets with a checksum - and two encoders of a length
//! are two ways to disagree about what the checksum covers. That disagreement surfaces as a ticket
//! rejected in the middle of an exchange, not as a failing test.
//!
//! Re-exported rather than wrapped so that `der::SEQUENCE`, `der::Reader` and the rest keep resolving
//! here, and so a `DerError` raised on one side is the same type the other side matches on.

pub use rrl_crypto::der::*;
