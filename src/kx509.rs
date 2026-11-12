//! The kx509 wire protocol (RFC 6717): a Kerberos ticket in, an X.509 certificate out.
//!
//! Carried on the KDC's own port, and the request is **not** a `KDC-REQ`: it begins with four
//! version octets (`00 00 02 00`) rather than an `[APPLICATION n]` tag, which is how a server tells
//! the two apart before decoding either. Everything that is the protocol lives here — both
//! directions, the framing and the two MACs — because the client and the server are in separate
//! crates and a second encoder would be a second way to disagree about a MAC that has no room for
//! interpretation.
//!
//! What is *not* here is what to do with the certificate: whether a realm issues one, to whom, and
//! from which key is policy, and policy belongs to the side that has a database.
//!
//! **Both MACs are HMAC-SHA1 whatever the enctype of the session key is** (RFC 6717 §3). The key is
//! used as octets, not through the enctype's own checksum construction; a peer that used the
//! enctype's checksum would produce something no implementation on the other side accepts, and this
//! MAC is the only authentication the payload carries.
//!
//! **The reply MAC covers the certificate's DER, not the encoding of the field that carries it.**
//! Feeding the `OCTET STRING`'s own tag and length produces a MAC no client computes; Heimdal feeds
//! `rep->certificate->data` for the same reason.

use crate::der;

/// The version prefix of every kx509 request: 2.0, as four octets.
pub const VERSION: [u8; 4] = [0x00, 0x00, 0x02, 0x00];

/// `[APPLICATION 35]`, the tag of `Kx509CSRPlus`.
///
/// Spelled out because it is the one tag in this protocol that is neither universal nor `[n]`, and a
/// reader who has not met an `APPLICATION` tag in a Kerberos message before will look for one.
pub const APP_CSR_PLUS: u8 = 0x60 | 35;

/// Client-side permanent problem (RFC 6717 §4): the request will not work if repeated.
pub const STATUS_CLIENT_BAD: i32 = 1;
/// Server-side permanent problem: the KDC is misconfigured, not overloaded.
pub const STATUS_SERVER_BAD: i32 = 4;
/// Where Kerberos protocol errors start, as Heimdal numbers them (RFC 6717 leaves the field open).
pub const KRB_ERROR_BASE: i32 = 1000;

/// What can go wrong reading or writing a kx509 message.
///
/// This module's own vocabulary rather than the crate's: a client that only wants to *ask* for a
/// certificate has no use for `NotARequest`, which is a server's way of saying "this is not a
/// kx509 request, try the KDC path".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The request does not begin with the version prefix.
    NotARequest(String),
    /// The octets are not the DER this protocol defines.
    Malformed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotARequest(why) => write!(f, "{why}"),
            Error::Malformed(why) => write!(f, "kx509: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// A decoded `Kx509Request`.
#[derive(Debug, Clone)]
pub struct Request {
    /// An AP-REQ, or empty for the availability probe.
    pub authenticator: Vec<u8>,
    /// `HMAC-SHA1(session_key, version || pk-key)`.
    pub pk_hash: Vec<u8>,
    /// A `Kx509CSRPlus`, or a bare `SubjectPublicKeyInfo`.
    pub pk_key: Vec<u8>,
}

impl Request {
    /// Whether `data` begins with the kx509 version, and so is a request rather than a KDC-REQ.
    pub fn claims(data: &[u8]) -> bool {
        data.starts_with(&VERSION)
    }

    /// The DER of the request: the version prefix and the `Kx509Request`.
    ///
    /// The three fields are bare `OCTET STRING`s — `Kx509Request` tags nothing, unlike almost every
    /// structure in RFC 4120 — and the order is the ASN.1's: authenticator, pk-hash, pk-key.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = VERSION.to_vec();
        out.extend(der::seq(&[
            der::octets(&self.authenticator),
            der::octets(&self.pk_hash),
            der::octets(&self.pk_key),
        ]));
        out
    }

    /// Decodes the DER after the version prefix.
    pub fn decode(data: &[u8]) -> Result<Request, Error> {
        let rest = data.strip_prefix(&VERSION[..]).ok_or_else(|| {
            Error::NotARequest("a kx509 request begins with the version 00 00 02 00".into())
        })?;
        let mut r = der::Reader::new(rest);
        let seq = r
            .next_tlv("Kx509Request")
            .map_err(|e| Error::NotARequest(format!("kx509: {e}")))?;
        if seq.tag != der::SEQUENCE {
            return Err(Error::NotARequest("Kx509Request is not a SEQUENCE".into()));
        }
        let mut f = der::Reader::new(seq.content);
        let field = |r: &mut der::Reader<'_>, what: &'static str| -> Result<Vec<u8>, Error> {
            let tlv = r
                .next_tlv(what)
                .map_err(|e| Error::NotARequest(format!("kx509 {what}: {e}")))?;
            if tlv.tag != der::OCTET_STRING {
                return Err(Error::NotARequest(format!(
                    "kx509 {what} is not an OCTET STRING"
                )));
            }
            Ok(tlv.content.to_vec())
        };
        Ok(Request {
            authenticator: field(&mut f, "authenticator")?,
            pk_hash: field(&mut f, "pk-hash")?,
            pk_key: field(&mut f, "pk-key")?,
        })
    }

    /// `HMAC-SHA1(session_key, version || pk-key)`: what proves the payload was built by whoever
    /// holds the session key, rather than paired with somebody else's ticket.
    pub fn mac(&self, session_key: &[u8]) -> Vec<u8> {
        hmac_sha1(session_key, &[&VERSION, &self.pk_key])
    }

    /// Whether [`Self::pk_hash`] is the MAC for `session_key`.
    ///
    /// Compared in constant time: a MAC check that returns early on the first differing octet leaks
    /// how much of a guess was right, which is the whole of what an attacker needs to finish it.
    pub fn verify_mac(&self, session_key: &[u8]) -> bool {
        constant_time_eq(&self.pk_hash, &self.mac(session_key))
    }
}

/// A `Kx509Response` under construction, and its DER.
#[derive(Debug, Clone, Default)]
pub struct Response {
    /// `error-code`, zero for success.
    pub error_code: i32,
    /// The reply MAC, present whenever the request was authenticated.
    pub hash: Option<Vec<u8>>,
    /// The certificate chain, DER.
    pub certificate: Option<Vec<u8>>,
    /// A message for the client's operator.
    pub text: Option<String>,
}

impl Response {
    /// An error answer with no MAC: what a probe, or a request that could not be authenticated,
    /// gets.
    pub fn error(code: i32, text: impl Into<String>) -> Response {
        Response {
            error_code: code,
            text: Some(text.into()),
            ..Response::default()
        }
    }

    /// The DER of the response.
    ///
    /// `error-code` is always written, even when it is zero and the ASN.1 says `DEFAULT`: the
    /// reply MAC covers its DER content, and a client that found the field absent would have to
    /// guess whether the KDC fed it zero or nothing. Both sides write it, both sides feed it.
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = vec![der::field(0, der::int(i64::from(self.error_code)))];
        if let Some(hash) = &self.hash {
            fields.push(der::field(1, der::octets(hash)));
        }
        if let Some(cert) = &self.certificate {
            fields.push(der::field(2, der::octets(cert)));
        }
        if let Some(text) = &self.text {
            // `VisibleString`.
            fields.push(der::field(3, der::tlv(0x1a, text.as_bytes())));
        }
        der::seq(&fields)
    }

    /// Decodes a `Kx509Response`.
    pub fn decode(data: &[u8]) -> Result<Response, Error> {
        let mut r = der::Reader::new(data);
        let seq = r
            .next_tlv("Kx509Response")
            .map_err(|e| Error::Malformed(format!("{e}")))?;
        if seq.tag != der::SEQUENCE {
            return Err(Error::Malformed("Kx509Response is not a SEQUENCE".into()));
        }
        let mut f = der::Reader::new(seq.content);
        let mut response = Response::default();
        while !f.is_empty() {
            let field = f
                .next_tlv("field")
                .map_err(|e| Error::Malformed(format!("{e}")))?;
            match field.tag {
                t if t == der::ctx(0) => {
                    let mut inner = der::Reader::new(field.content);
                    response.error_code = inner
                        .int()
                        .map_err(|e| Error::Malformed(format!("error-code: {e}")))?
                        as i32;
                }
                t if t == der::ctx(1) => response.hash = Some(octets_in(field.content)?),
                t if t == der::ctx(2) => response.certificate = Some(octets_in(field.content)?),
                t if t == der::ctx(3) => {
                    let mut inner = der::Reader::new(field.content);
                    let text = inner
                        .next_tlv("text")
                        .map_err(|e| Error::Malformed(format!("text: {e}")))?;
                    response.text = Some(String::from_utf8_lossy(text.content).into_owned());
                }
                // Not fatal: the ASN.1's CHOICE-style growth is not something a client should
                // refuse a valid certificate over.
                _ => {}
            }
        }
        Ok(response)
    }

    /// `HMAC-SHA1(session_key, version || error-code || certificate)`.
    ///
    /// The certificate enters as its own DER. A response that failed has no certificate, and the
    /// MAC over `version || error-code` is what a client checks then — which is why the error code
    /// is fed as the content of an `INTEGER` rather than as four octets.
    pub fn mac(&self, session_key: &[u8]) -> Vec<u8> {
        let certificate = self.certificate.as_deref().unwrap_or(&[]);
        hmac_sha1(
            session_key,
            &[&VERSION, &int_content(self.error_code), certificate],
        )
    }

    /// Whether [`Self::hash`] is the MAC for `session_key`.
    pub fn verify_mac(&self, session_key: &[u8]) -> bool {
        match &self.hash {
            Some(hash) => constant_time_eq(hash, &self.mac(session_key)),
            None => false,
        }
    }
}

/// `HMAC-SHA1(key, parts)` — RFC 6717's MAC, whatever the enctype is.
pub fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key)
        .expect("HMAC accepts a key of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

/// The DER content of an `INTEGER`, which is what the reply MAC covers (RFC 6717 §3).
fn int_content(v: i32) -> Vec<u8> {
    let encoded = der::int(i64::from(v));
    // Strip the tag and the length: the value's content is what RFC 6717 names, "exclusive of the
    // tag and length".
    let mut r = der::Reader::new(&encoded);
    r.next_tlv("INTEGER")
        .map(|tlv| tlv.content.to_vec())
        .unwrap_or_default()
}

/// The OCTET STRING inside a constructed field.
fn octets_in(content: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = der::Reader::new(content);
    let inner = r
        .next_tlv("value")
        .map_err(|e| Error::Malformed(format!("{e}")))?;
    if inner.tag != der::OCTET_STRING {
        return Err(Error::Malformed(format!(
            "expected an OCTET STRING, found tag {:#04x}",
            inner.tag
        )));
    }
    Ok(inner.content.to_vec())
}

/// Whether two octet strings are equal, in time that does not depend on where they differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The CSR out of a `Kx509CSRPlus`.
///
/// A bare `SubjectPublicKeyInfo` is refused by name: it carries no proof that its sender holds the
/// private half, and a realm that issued certificates for such keys would be issuing them for
/// anybody. That refusal belongs to the protocol, not to one server's policy, so it is here — a
/// client that sends a bare key should find out from the shared code for the format.
///
/// Both taggings are accepted: `[APPLICATION 35] { SEQUENCE { csr } }` as the ASN.1's default
/// `EXPLICIT TAGS` gives it, and the implicit form an encoder might produce. The tag alone cannot
/// say which was meant, and refusing the other would refuse a working client.
pub fn csr_from_plus(pk_key: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = der::Reader::new(pk_key);
    let plus = r
        .next_tlv("pk-key")
        .map_err(|e| Error::Malformed(format!("the pk-key: {e}")))?;
    if plus.tag != APP_CSR_PLUS {
        return Err(Error::Malformed(format!(
            "the pk-key is tag {:#04x}, and only a Kx509CSRPlus ([APPLICATION 35]) is accepted: a \
             bare public key carries no proof that its sender holds the private half",
            plus.tag
        )));
    }
    let mut f = der::Reader::new(plus.content);
    let first = f
        .next_tlv("csr")
        .map_err(|e| Error::Malformed(format!("the csr: {e}")))?;
    let csr = if first.tag == der::SEQUENCE {
        let mut inner = der::Reader::new(first.content);
        inner
            .next_tlv("csr")
            .map_err(|e| Error::Malformed(format!("the csr: {e}")))?
    } else {
        first
    };
    if csr.tag != der::OCTET_STRING {
        return Err(Error::Malformed(format!(
            "a Kx509CSRPlus carries the CSR as an OCTET STRING, not {:#04x}",
            csr.tag
        )));
    }
    Ok(csr.content.to_vec())
}

/// A `Kx509CSRPlus` around `csr`: `[APPLICATION 35] { SEQUENCE { OCTET STRING csr } }`.
///
/// The explicit form, because that is what `EXPLICIT TAGS` gives and what the server reads first.
pub fn plus_from_csr(csr: &[u8]) -> Vec<u8> {
    der::cons(APP_CSR_PLUS, &[der::seq(&[der::octets(csr)])])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            authenticator: b"an AP-REQ".to_vec(),
            pk_hash: Vec::new(),
            pk_key: plus_from_csr(b"a CSR"),
        }
    }

    /// The prefix decides which protocol a message belongs to, and it is four octets: a KDC-REQ
    /// starts with `[APPLICATION 10]`, so this cannot be confused with one.
    #[test]
    fn the_version_prefix_is_what_claims_a_request() {
        let encoded = request().encode();
        assert_eq!(&encoded[..4], &VERSION);
        assert!(Request::claims(&encoded));
        assert!(!Request::claims(&[0x6a, 0x81]));
        assert!(matches!(
            Request::decode(&[0x6a, 0x81]),
            Err(Error::NotARequest(_))
        ));
    }

    /// A request survives the round trip with its three fields intact, and a MAC computed one way is
    /// what the other side verifies.
    #[test]
    fn a_request_round_trips_and_its_mac_verifies() {
        let key = b"the ticket's session key";
        let mut sent = request();
        sent.pk_hash = sent.mac(key);
        let decoded = Request::decode(&sent.encode()).expect("decodes");
        assert_eq!(decoded.authenticator, sent.authenticator);
        assert_eq!(decoded.pk_key, sent.pk_key);
        assert!(decoded.verify_mac(key));

        // A different key, and a different payload under the same key: both fail.
        assert!(!decoded.verify_mac(b"another key"));
        let mut tampered = decoded.clone();
        tampered.pk_key = plus_from_csr(b"a different CSR");
        assert!(!tampered.verify_mac(key));
    }

    /// The MAC is HMAC-SHA1 over `version || pk-key` and nothing else — computed here from the
    /// definition rather than asked of the code under test.
    #[test]
    fn the_request_mac_is_hmac_sha1_over_the_version_and_the_key() {
        use hmac::{Hmac, KeyInit, Mac};
        let key = b"a key";
        let sent = request();
        let mut expected = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key).unwrap();
        expected.update(&VERSION);
        expected.update(&sent.pk_key);
        let expected = expected.finalize().into_bytes().to_vec();
        assert_eq!(sent.mac(key), expected);
        assert_eq!(sent.mac(key).len(), 20, "SHA-1's 20 octets");
    }

    /// The reply MAC covers the certificate's DER, not the OCTET STRING that carries it: a client
    /// computes it over `rep->certificate->data`, so both sides feed the bare DER.
    #[test]
    fn the_reply_mac_covers_the_certificate_and_not_its_wrapper() {
        use hmac::{Hmac, KeyInit, Mac};
        let key = b"a key";
        let certificate = b"a certificate, in DER".to_vec();
        let response = Response {
            error_code: 0,
            hash: None,
            certificate: Some(certificate.clone()),
            text: None,
        };

        let mut expected = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key).unwrap();
        expected.update(&VERSION);
        expected.update(&int_content(0));
        expected.update(&certificate);
        assert_eq!(response.mac(key), expected.finalize().into_bytes().to_vec());

        // And the encoding puts the DER in the field once, not twice.
        let encoded = response.encode();
        let decoded = Response::decode(&encoded).expect("decodes");
        assert_eq!(decoded.certificate.as_deref(), Some(&certificate[..]));
    }

    /// `error-code` is written even when it is zero, because the MAC covers its content and a
    /// client that found it absent would be guessing.
    #[test]
    fn a_zero_error_code_is_written_out() {
        let encoded = Response::default().encode();
        let decoded = Response::decode(&encoded).expect("decodes");
        assert_eq!(decoded.error_code, 0);
        // `a0 03 02 01 00`: the field is present, and its INTEGER is a single zero octet.
        assert!(
            encoded
                .windows(5)
                .any(|w| w == [0xa0, 0x03, 0x02, 0x01, 0x00])
        );
    }

    /// An error answer with no MAC does not verify — a client must not treat "the server said no"
    /// as "the server answered".
    #[test]
    fn a_mac_less_answer_never_verifies() {
        let error = Response::error(STATUS_CLIENT_BAD, "no");
        assert!(!error.verify_mac(b"a key"));
        let decoded = Response::decode(&error.encode()).expect("decodes");
        assert_eq!(decoded.error_code, STATUS_CLIENT_BAD);
        assert_eq!(decoded.text.as_deref(), Some("no"));
        assert!(!decoded.verify_mac(b"a key"));
    }

    /// The CSR wrapper is read in both taggings, and a bare key is refused by name.
    #[test]
    fn the_csr_wrapper_is_read_in_both_taggings() {
        let csr = b"a CSR, in DER";
        let explicit = plus_from_csr(csr);
        assert_eq!(csr_from_plus(&explicit).expect("the explicit form"), csr);

        // The implicit form: the OCTET STRING straight inside `[APPLICATION 35]`.
        let implicit = der::cons(APP_CSR_PLUS, &[der::octets(csr)]);
        assert_eq!(csr_from_plus(&implicit).expect("the implicit form"), csr);

        // A bare `SubjectPublicKeyInfo`: a SEQUENCE, and not this tag.
        let bare = der::seq(&[der::seq(&[der::int(1)])]);
        let err = csr_from_plus(&bare).expect_err("a bare key is refused");
        assert!(err.to_string().contains("private half"), "{err}");
    }
}
