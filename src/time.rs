//! Kerberos `KerberosTime` formatting, re-exported from the crypto layer.
//!
//! It moved there with the DER encoder (RRL-7.8): a GeneralisedTime is a DER value, and a parser for
//! one belongs beside the reader that frames it.

pub use rrl_crypto::time::*;
