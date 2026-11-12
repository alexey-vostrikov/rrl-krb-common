//! Kerberos on the wire: the structures a KDC and an acceptor have to agree about.
//!
//! RFC 4120 describes one protocol with two roles — a KDC that answers and a client that asks —
//! and the structures in the middle are the same in both directions. A ticket an acceptor parses
//! is a ticket a KDC built; a PAC a KDC signs is a PAC a server verifies. Writing those structures
//! twice means two decoders that can disagree about the encoding of the field a checksum covers,
//! and that disagreement shows up as a rejected ticket in the middle of an authentication
//! exchange, not as a failing test.
//!
//! So this crate holds the shared middle:
//!
//! * [`der`] — ASN.1 DER, strict about the things DER is strict about (minimal lengths, minimal
//!   INTEGERs) because a request's checksum is computed over the exact octets of a structure;
//! * [`time`] — `KerberosTime`, by hand, so that a date which never existed is refused rather
//!   than normalised into one that did;
//! * [`name`] — `PrincipalName` and realms, compared without the name type, the way MIT and
//!   Heimdal compare them;
//! * [`msg`] — `EncryptedData`, `Ticket`, `EncTicketPart`, `EncKdcRepPart`, `KDC-REP`,
//!   `KRB-ERROR`, `PA-DATA`;
//! * [`pac`] — MS-PAC and the `KERB_VALIDATION_INFO` inside it, the authorization data Windows
//!   and MIT put in tickets.
//!
//! The crypto underneath is [`rrl_crypto`], shared with the KDC: two copies of a key derivation
//! are two ways to produce a ticket nobody can open.
//!
//! What is deliberately *not* here: AS or TGS request handling, replay caches, credential caches,
//! GSS. Those differ by role, and it is the role that decides what is correct.

pub mod der;
pub mod error;
pub mod kx509;
pub mod logon_info;
pub mod msg;
pub mod name;
pub mod pac;
pub mod time;

pub use error::{Error, Result};

/// The crypto crate, under the name the message code already used for it.
pub use rrl_crypto as crypto;
pub use rrl_crypto::{Cipher, Enctype, Key, KeyUse};

pub use name::Principal;
