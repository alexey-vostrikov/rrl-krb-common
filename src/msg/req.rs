//! `KDC-REQ`, which is what a KDC reads: `AS-REQ` and `TGS-REQ` share the same
//! body, and the body is the only part whose exact octets matter for a
//! checksum (§5.4.1's `PA-TGS-REQ` authenticator covers it byte for byte).
//!
//! [`KdcReqBody::raw`] keeps those octets, because re-encoding a decoded body
//! is not the same thing: a client is allowed to order or pad nothing, but any
//! difference would break the checksum, so the KDC verifies over what arrived.

use crate::der::{self, Fields, Reader};
use crate::error::{Error, Result};
use crate::name::Principal;

use super::{AS_REQ, TGS_REQ};

/// A `KDC-REQ`: an `AS-REQ` or a `TGS-REQ`.
#[derive(Clone, Debug)]
pub struct KdcReq {
    /// [`AS_REQ`] or [`TGS_REQ`].
    pub msg_type: i64,
    /// `PA-DATA`, in the order the client sent it.
    pub padata: Vec<(i32, Vec<u8>)>,
    /// The body.
    pub body: KdcReqBody,
    /// The exact octets of the `KDC-REQ-BODY` SEQUENCE, tag included — what a
    /// `PA-TGS-REQ` authenticator's checksum is computed over.
    pub raw_body: Vec<u8>,
}

/// `KDC-REQ-BODY ::= SEQUENCE { ... }`.
#[derive(Clone, Debug)]
pub struct KdcReqBody {
    /// `KDCOptions`.
    pub kdc_options: u32,
    /// The client, when the request names one.
    pub cname: Option<Principal>,
    /// The realm the request is for.
    pub realm: String,
    /// The service the ticket is wanted for.
    pub sname: Option<Principal>,
    /// `from` — when a postdated ticket should start.
    pub from: Option<i64>,
    /// `till` — when it should end. Zero means "as long as you allow".
    pub till: i64,
    /// `rtime` — the requested renewable lifetime.
    pub rtime: Option<i64>,
    /// The nonce to echo.
    pub nonce: u32,
    /// The requested enctypes, as numbers: a client may ask for ones this KDC
    /// does not implement, and that must not fail the whole request.
    pub etypes: Vec<i32>,
    /// `addresses`, kept as the `HostAddresses` SEQUENCE it arrived as.
    pub addresses: Option<Vec<u8>>,
    /// `enc-authorization-data`, kept encoded.
    pub enc_authorization_data: Option<Vec<u8>>,
    /// `additional-tickets`, kept as the `SEQUENCE OF Ticket` it arrived as: a
    /// user-to-user request puts the server's own TGT here, and the KDC needs
    /// the ticket's exact octets to find its session key.
    pub additional_tickets: Option<Vec<u8>>,
}

/// Which request the octets claim to be: its application tag and the message type that goes with it.
///
/// A `TGS-REQ` arriving at the AS port is refused here, by tag, rather than answered with whatever
/// the body happens to decode to — the tag and the body agree or the message is not a request this
/// implementation serves.
fn request_kind(data: &[u8]) -> Result<(u8, i64)> {
    match data.first() {
        Some(0x6a) => Ok((10, AS_REQ)),
        Some(0x6c) => Ok((12, TGS_REQ)),
        Some(&other) => Err(Error::NotARequest(format!(
            "application tag {other:#04x}; expected AS-REQ (0x6a) or TGS-REQ (0x6c)"
        ))),
        None => Err(Error::NotARequest("empty message".into())),
    }
}

impl KdcReq {
    /// Decodes a whole `[APPLICATION 10]` / `[APPLICATION 12]` request.
    ///
    /// The application tag decides which message this is: a `TGS-REQ` sent to
    /// the AS port is refused here rather than answered with something it did
    /// not ask for.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (app_tag, msg_type) = request_kind(data)?;
        let f = Fields::parse_app("KDC-REQ", app_tag, data)?;
        super::expect_pvno(&f, "KDC-REQ", 1)?;
        super::expect_msg_type(&f, "KDC-REQ", 2, msg_type)?;
        // The body is kept as it arrived — the whole `KDC-REQ-BODY` SEQUENCE, tag and length
        // included — because a client's PA-FX-FAST checksum is over exactly those octets, and the
        // decoder is handed the content inside them instead.
        let raw_body = f.bytes(4, "KDC-REQ")?.to_vec();
        let content = super::sequence_at(&f, 4, "KDC-REQ")?;
        Ok(KdcReq {
            msg_type,
            padata: super::pa_data_at(&f, 3, "KDC-REQ")?,
            body: KdcReqBody::decode(content)?,
            raw_body,
        })
    }

    /// The `PA-DATA` value of type `pa_type`, if the client sent one.
    pub fn padata(&self, pa_type: i32) -> Option<&[u8]> {
        self.padata
            .iter()
            .find(|(t, _)| *t == pa_type)
            .map(|(_, v)| v.as_slice())
    }
}

impl KdcReqBody {
    /// Decodes the content of a `KDC-REQ-BODY` SEQUENCE.
    pub fn decode(content: &[u8]) -> Result<Self> {
        let ctx: &'static str = "KDC-REQ-BODY";
        let f = Fields::parse(ctx, content)?;
        let realm = f.string(2, ctx)?;
        let w = window(&f, ctx)?;
        Ok(KdcReqBody {
            kdc_options: f.flags32(0, ctx)?,
            cname: opt_principal(&f, 1, ctx, &realm)?,
            sname: opt_principal(&f, 3, ctx, &realm)?,
            realm,
            from: w.from,
            till: w.till,
            rtime: w.rtime,
            nonce: w.nonce,
            etypes: w.etypes,
            addresses: w.addresses,
            enc_authorization_data: w.enc_authorization_data,
            additional_tickets: w.additional_tickets,
        })
    }
}

/// A principal the client may or may not have named.
fn opt_principal(
    f: &Fields<'_>,
    tag: u8,
    ctx: &'static str,
    realm: &str,
) -> Result<Option<Principal>> {
    match f.opt(tag) {
        None => Ok(None),
        Some(_) => Ok(Some(Principal::decode_field(f, tag, ctx, realm)?)),
    }
}

/// What the request asks for in time, in tickets, and in enctypes.
///
/// These fields travel together — a start time without the end time it is measured against says
/// nothing — so they are read in one place and handed over as one value, rather than as eight
/// separate reads inside the decoder.
struct Window {
    from: Option<i64>,
    till: i64,
    rtime: Option<i64>,
    nonce: u32,
    etypes: Vec<i32>,
    addresses: Option<Vec<u8>>,
    enc_authorization_data: Option<Vec<u8>>,
    additional_tickets: Option<Vec<u8>>,
}

fn window(f: &Fields<'_>, ctx: &'static str) -> Result<Window> {
    Ok(Window {
        from: super::opt_time(f, 4, ctx)?,
        till: super::as_time(ctx, f.bytes(5, ctx)?)?,
        rtime: super::opt_time(f, 6, ctx)?,
        nonce: f.u32(7, ctx)?,
        etypes: etypes_at(f, ctx)?,
        addresses: f.bytes(9, ctx).ok().map(<[u8]>::to_vec),
        enc_authorization_data: f.opt_bytes(10).map(<[u8]>::to_vec),
        additional_tickets: f.opt_bytes(11).map(<[u8]>::to_vec),
    })
}

/// The `SEQUENCE OF Int32` of enctypes, in the order the client prefers them.
fn etypes_at(f: &Fields<'_>, ctx: &'static str) -> Result<Vec<i32>> {
    let mut r = Reader::new(super::sequence_at(f, 8, ctx)?);
    let mut etypes = Vec::new();
    while !r.is_empty() {
        etypes.push(der::as_int(ctx, r.expect_in(ctx, der::INTEGER)?)? as i32);
    }
    Ok(etypes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{PA_ENC_TIMESTAMP, encode_pa_data, kdc_options};

    /// An AS-REQ built the way a client builds one: the shape matters, because
    /// the round trip is what the acceptance test depends on.
    fn as_req_bytes() -> Vec<u8> {
        let alice = Principal::parse("alice@R").unwrap();
        let body = der::seq(&[
            der::field(
                0,
                der::flags32(kdc_options::FORWARDABLE | kdc_options::RENEWABLE),
            ),
            der::field(1, alice.encode_name()),
            der::field(2, der::general_string("R")),
            der::field(3, Principal::krbtgt("R").encode_name()),
            der::field(5, der::time(1_700_003_600)),
            der::field(7, der::int(0x1234_5678)),
            der::field(8, der::seq(&[der::int(18), der::int(17)])),
        ]);
        der::cons(
            der::app(10),
            &[der::seq(&[
                der::field(1, der::int(5)),
                der::field(2, der::int(10)),
                der::field(3, encode_pa_data(&[(PA_ENC_TIMESTAMP, b"opaque".to_vec())])),
                der::field(4, body),
            ])],
        )
    }

    #[test]
    fn decodes_an_as_req_field_by_field() {
        let req = KdcReq::decode(&as_req_bytes()).unwrap();
        assert_eq!(req.msg_type, AS_REQ);
        assert_eq!(req.body.realm, "R");
        assert_eq!(
            req.body.cname.as_ref().unwrap().components,
            ["alice"],
            "the client must survive decoding"
        );
        assert_eq!(req.body.sname.as_ref().unwrap(), &Principal::krbtgt("R"));
        assert_eq!(req.body.nonce, 0x1234_5678);
        assert_eq!(req.body.etypes, vec![18, 17]);
        assert_eq!(req.body.till, 1_700_003_600);
        assert_ne!(req.body.kdc_options & kdc_options::FORWARDABLE, 0);
        assert_eq!(req.padata(PA_ENC_TIMESTAMP), Some(&b"opaque"[..]));
        assert!(req.padata(19).is_none());
        // The body's own octets are kept, for the TGS checksum later.
        assert_eq!(req.raw_body[0], der::SEQUENCE);
    }

    #[test]
    fn a_tgs_req_is_recognised_as_one() {
        let body = der::seq(&[
            der::field(0, der::flags32(0)),
            der::field(2, der::general_string("R")),
            der::field(3, Principal::krbtgt("R").encode_name()),
            der::field(5, der::time(1_700_003_600)),
            der::field(7, der::int(1)),
            der::field(8, der::seq(&[der::int(18)])),
        ]);
        let bytes = der::cons(
            der::app(12),
            &[der::seq(&[
                der::field(1, der::int(5)),
                der::field(2, der::int(12)),
                der::field(4, body),
            ])],
        );
        assert_eq!(KdcReq::decode(&bytes).unwrap().msg_type, TGS_REQ);
    }

    #[test]
    fn refuses_what_is_not_a_request() {
        assert!(KdcReq::decode(&[]).is_err());
        assert!(
            KdcReq::decode(&[0x6e, 0x00]).is_err(),
            "KRB-ERROR is not a request"
        );
        // pvno 4: not Kerberos 5.
        let bad = der::cons(
            der::app(10),
            &[der::seq(&[
                der::field(1, der::int(4)),
                der::field(2, der::int(10)),
            ])],
        );
        assert!(KdcReq::decode(&bad).is_err());
        // An application tag of AS-REQ carrying msg-type 12.
        let bad = der::cons(
            der::app(10),
            &[der::seq(&[
                der::field(1, der::int(5)),
                der::field(2, der::int(12)),
            ])],
        );
        assert!(KdcReq::decode(&bad).is_err());
    }

    #[test]
    fn an_unknown_enctype_in_the_list_is_not_fatal() {
        let body = der::seq(&[
            der::field(0, der::flags32(0)),
            der::field(2, der::general_string("R")),
            der::field(5, der::time(1_700_003_600)),
            der::field(7, der::int(1)),
            // 23 is RC4, which this KDC does not implement; 18 is AES-256.
            der::field(8, der::seq(&[der::int(23), der::int(18)])),
        ]);
        let bytes = der::cons(
            der::app(10),
            &[der::seq(&[
                der::field(1, der::int(5)),
                der::field(2, der::int(10)),
                der::field(4, body),
            ])],
        );
        assert_eq!(KdcReq::decode(&bytes).unwrap().body.etypes, vec![23, 18]);
    }
}
