//! What can go wrong while reading or writing a Kerberos message.
//!
//! Deliberately narrow. This crate knows about the wire — DER, the RFC 4120 structures, the PAC —
//! and nothing about who is asking: a KDC that must not tell a client whether a principal exists,
//! and an acceptor that wants to say exactly why a token failed, both need their own errors on top
//! of these. Merging the two role-specific sets into one enum would force each side to carry
//! variants it must never emit, which is how a "principal unknown" leaks into a client's reply.

use std::fmt;

/// A message could not be read, or could not be written.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The octets are not the DER this crate expects.
    Der(crate::der::DerError),
    /// An enctype this crate does not implement (it implements 17, 18, 19 and 20).
    UnsupportedEnctype(i32),
    /// A key whose length does not match its enctype.
    KeyLength {
        /// The enctype the key claims.
        enctype: crate::Enctype,
        /// The length that enctype requires.
        want: usize,
        /// The length that arrived.
        got: usize,
    },
    /// A cryptographic operation failed: a bad tag, a short ciphertext.
    Crypto(String),
    /// The octets are not a `KDC-REQ` this implementation will answer.
    NotARequest(String),
    /// The message decoded, but says something no implementation may accept.
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Der(e) => write!(f, "{e}"),
            Error::UnsupportedEnctype(id) => {
                write!(
                    f,
                    "enctype {id} is not one this implementation has (17, 18, 19, 20)"
                )
            }
            Error::KeyLength { enctype, want, got } => {
                write!(f, "enctype {enctype:?} takes a {want}-octet key, got {got}")
            }
            Error::Crypto(s) => write!(f, "crypto: {s}"),
            Error::NotARequest(s) => write!(f, "message is not a KDC-REQ: {s}"),
            Error::Protocol(s) => write!(f, "protocol: {s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Der(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::der::DerError> for Error {
    fn from(e: crate::der::DerError) -> Self {
        Error::Der(e)
    }
}

/// The same failures arriving from `rrl-crypto`.
///
/// Kept distinct from [`Error::Crypto`] rather than flattened to a string, because the protocol
/// code depends on the difference: an unimplemented enctype has to answer `ETYPE_NOSUPP`, and a
/// failed integrity check has to answer `BAD_INTEGRITY`.
impl From<crate::crypto::Error> for Error {
    fn from(e: crate::crypto::Error) -> Self {
        match e {
            crate::crypto::Error::UnsupportedEnctype(id) => Error::UnsupportedEnctype(id),
            crate::crypto::Error::KeyLength { enctype, want, got } => {
                Error::KeyLength { enctype, want, got }
            }
            // The inner variant already carries its layer's name in its `Display`, and this enum's
            // own `Display` writes "crypto: " in front of whatever arrives: passing the formatted
            // error through produced "crypto: crypto: bad tag", which reads like two failures in a
            // row. The detail is what belongs here; the prefix is written once, by the printer.
            crate::crypto::Error::Crypto(detail) => Error::Crypto(detail),
            other => Error::Crypto(other.to_string()),
        }
    }
}

/// Result of anything in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A failure naming the value being parsed.
pub fn protocol<T>(context: &str, detail: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(format!("{context}: {}", detail.into())))
}

/// The RFC 4120 §7.5 error codes, by the names the RFC gives them.
///
/// A KDC writes these into `KRB-ERROR` and a client compares against them; keeping the numbers
/// in one place is what stops a reply from carrying a code that means something else.
pub mod codes {
    /// No error.
    pub const KDC_ERR_NONE: i32 = 0;
    /// The client principal is not in the database.
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;
    /// The service principal is not in the database.
    pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;
    /// The principal name resolves to more than one entry.
    pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE: i32 = 8;
    /// The request asks for a lifetime that ends before it starts.
    pub const KDC_ERR_NEVER_VALID: i32 = 11;
    /// The realm's policy forbids what was asked for (a proxiable ticket, a
    /// postdated one, a service that may not be issued).
    pub const KDC_ERR_POLICY: i32 = 12;
    /// The request asked for an option that does not apply: renewing a ticket
    /// that is not renewable, validating one that is not invalid.
    pub const KDC_ERR_BADOPTION: i32 = 13;
    /// No requested enctype is one this KDC implements.
    pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14;
    /// The account is locked, disabled or expired.
    pub const KDC_ERR_CLIENT_REVOKED: i32 = 18;
    /// Pre-authentication data did not verify.
    pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
    /// More pre-authentication is needed; `e-data` carries METHOD-DATA.
    pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
    /// Continue: the mechanism needs another round (RFC 6113 §3.1). Not a refusal —
    /// the client answers with another request, resuming from the cookie.
    pub const KDC_ERR_MORE_PREAUTH_DATA_REQUIRED: i32 = 91;
    /// The requested server does not match the ticket granted.
    pub const KDC_ERR_SERVER_NOMATCH: i32 = 26;
    /// The service requires a user-to-user ticket.
    pub const KDC_ERR_MUST_USE_USER2USER: i32 = 27;
    /// This KDC cannot answer; the client should try another.
    pub const KDC_ERR_SVC_UNAVAILABLE: i32 = 29;
    /// The reply does not fit in a datagram; the client should retry over TCP.
    pub const KDC_ERR_RESPONSE_TOO_BIG: i32 = 52;
    /// The realm in the request is not one this KDC serves.
    pub const KDC_ERR_WRONG_REALM: i32 = 68;
    /// RFC 4120 §7.5.9: the KDC has no key to encrypt the reply with. Anonymous PKINIT
    /// says this when the realm has no KDC certificate (RFC 8062 §4.1).
    pub const KDC_ERR_NULL_KEY: i32 = 21;
    /// RFC 4556 §3.2.1: a PKINIT client asked for key transport where the exchange needs
    /// Diffie-Hellman (which is also the anonymous case, where it has no key pair at all).
    pub const KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED: i32 = 81;
    /// RFC 6113 §5.4.4.2: a `fast-options` bit this KDC does not implement, set by the
    /// client. Bits 1 through 15 are critical, so an unknown one must fail the request
    /// rather than be ignored — the client asked for something it will not get.
    pub const KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS: i32 = 93;
    /// A decrypted value failed its integrity check.
    pub const KRB_AP_ERR_BAD_INTEGRITY: i32 = 31;
    /// The ticket has expired.
    pub const KRB_AP_ERR_TKT_EXPIRED: i32 = 32;
    /// The ticket is not valid yet.
    pub const KRB_AP_ERR_TKT_NYV: i32 = 33;
    /// The clocks differ by more than the allowance.
    pub const KRB_AP_ERR_SKEW: i32 = 37;
    /// The client's address is not one the ticket allows.
    pub const KRB_AP_ERR_BADADDR: i32 = 38;
    /// The protocol version is not 5.
    pub const KRB_AP_ERR_BADVERSION: i32 = 39;
    /// The message type is wrong for this exchange.
    pub const KRB_AP_ERR_MSG_TYPE: i32 = 40;
    /// The message could not be decoded or was altered.
    pub const KRB_AP_ERR_MODIFIED: i32 = 41;
    /// The authenticator names a different principal than the ticket does.
    pub const KRB_AP_ERR_BADMATCH: i32 = 36;
    /// RFC 4120 §7.5.3: an authenticator that has been seen before, inside the clock skew.
    pub const KRB_AP_ERR_REPEAT: i32 = 34;
    /// The ticket is postdated and has not been validated.
    pub const KRB_AP_ERR_TKT_INVALID: i32 = 49;
    /// A checksum that must be present is absent, or is of the wrong type.
    pub const KRB_AP_ERR_INAPP_CKSUM: i32 = 50;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant prints something that names its own failure.
    ///
    /// `Display` is the only account an operator gets when a message is refused: the protocol code
    /// is a number, and the detail lives in this text. Three of the six arms had never been
    /// formatted by a test, and one of them states a fact that moves - which enctypes this build
    /// implements - so the text is pinned here rather than in a comment.
    #[test]
    fn every_variant_says_what_failed() {
        let der = Error::Der(crate::der::DerError("Certificate: not a SEQUENCE".into()));
        assert_eq!(der.to_string(), "DER: Certificate: not a SEQUENCE");

        assert_eq!(
            Error::UnsupportedEnctype(23).to_string(),
            "enctype 23 is not one this implementation has (17, 18, 19, 20)"
        );
        assert_eq!(
            Error::KeyLength {
                enctype: crate::Enctype::Aes256Sha384,
                want: 32,
                got: 16,
            }
            .to_string(),
            "enctype Aes256Sha384 takes a 32-octet key, got 16"
        );
        assert_eq!(
            Error::Crypto("bad tag".into()).to_string(),
            "crypto: bad tag"
        );
        assert_eq!(
            Error::NotARequest("empty message".into()).to_string(),
            "message is not a KDC-REQ: empty message"
        );
        assert_eq!(
            Error::Protocol("pvno is 4".into()).to_string(),
            "protocol: pvno is 4"
        );
    }

    /// `source` answers with the cause it has and nothing more: a DER failure wraps one, and every
    /// other variant is a statement of its own, not a wrapper.
    #[test]
    fn only_the_wrapped_error_reports_a_source() {
        use std::error::Error as _;
        let der = Error::Der(crate::der::DerError("Certificate: not a SEQUENCE".into()));
        assert!(der.source().is_some(), "a DER failure has a cause");

        for e in [
            Error::UnsupportedEnctype(23),
            Error::Crypto("bad tag".into()),
            Error::NotARequest("empty message".into()),
            Error::Protocol("pvno is 4".into()),
        ] {
            assert!(e.source().is_none(), "{e} is its own cause");
        }
    }

    /// A crypto failure keeps the two variants the protocol code reads and flattens the rest.
    ///
    /// The difference is load-bearing: an unimplemented enctype answers `ETYPE_NOSUPP` and a failed
    /// integrity check answers `BAD_INTEGRITY`, so a conversion that flattened everything to a
    /// string would turn both into `KRB_ERR_GENERIC` without any test noticing.
    #[test]
    fn a_crypto_failure_keeps_the_variants_the_protocol_code_reads() {
        let unsupported: Error = crate::crypto::Error::UnsupportedEnctype(21).into();
        assert!(
            matches!(unsupported, Error::UnsupportedEnctype(21)),
            "{unsupported:?}"
        );

        let wrong: Error = crate::crypto::Error::KeyLength {
            enctype: crate::Enctype::Aes128Sha256,
            want: 16,
            got: 32,
        }
        .into();
        match wrong {
            Error::KeyLength { want, got, .. } => assert_eq!((want, got), (16, 32)),
            other => panic!("expected KeyLength, got {other:?}"),
        }

        let other: Error = crate::crypto::Error::Crypto("bad tag".into()).into();
        assert_eq!(other.to_string(), "crypto: bad tag");

        // The DER conversion is the plain one.
        let der: Error = crate::der::DerError("Principal: bad name".into()).into();
        assert!(matches!(der, Error::Der(_)), "{der:?}");
    }

    /// `protocol()` names the context it was given, and returns an error rather than a value: it
    /// exists so a call site does not have to build the `format!` itself.
    #[test]
    fn protocol_names_the_context() {
        let e = protocol::<()>("KDC-REQ-BODY", "field 2 is absent").unwrap_err();
        assert_eq!(e.to_string(), "protocol: KDC-REQ-BODY: field 2 is absent");
    }
}
