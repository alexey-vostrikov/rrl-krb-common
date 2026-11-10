# rrl-krb

Kerberos on the wire: the structures a KDC and an acceptor have to agree about.

RFC 4120 describes one protocol with two roles — a KDC that answers and a client that asks — and
the structures in the middle are the same in both directions. A ticket an acceptor parses is a
ticket a KDC built; a PAC a KDC signs is a PAC a server verifies. Written twice, those are two
decoders that can disagree about the encoding of the field a checksum covers, and that
disagreement surfaces as a rejected ticket in the middle of an authentication exchange rather than
as a failing test.

This crate holds the shared middle and nothing else:

| module | what it is |
| --- | --- |
| `der` | ASN.1 DER, strict about what DER is strict about |
| `time` | `KerberosTime`, by hand, so that 30 February is refused and not normalised |
| `name` | `PrincipalName` and realms, compared without the name type |
| `msg` | `EncryptedData`, `Ticket`, `EncTicketPart`, `EncKdcRepPart`, `KDC-REP`, `KRB-ERROR`, `PA-DATA` |
| `pac` | MS-PAC and the `KERB_VALIDATION_INFO` inside it |
| `error` | the errors of reading and writing those, and the RFC 4120 §7.5 codes |

The crypto underneath is [`rrl-crypto`](https://github.com/alexey-vostrikov/rrl-crypto), shared
with the KDC: two copies of a key derivation are two ways to produce a ticket nobody can open.

## What is deliberately not here

AS and TGS request handling, replay caches, credential caches, GSS, SPNEGO. Those differ by role,
and it is the role that decides what is correct: a KDC must not tell a client whether a principal
exists, while an acceptor has to say exactly why a token failed. Merging them would give each side
variants it must never emit.

## Two vocabularies, one decoder

`Reader` and `Fields` carry two sets of accessors. `next`/`expect`/`get`/`opt` are the short forms
the acceptor's parser was written against; `next_tlv`/`expect_in`/`bytes`/`opt_bytes` take a
context string, because a message like `AS-REQ: missing field [2]` is actionable and
`missing field [2]` is not. Both land in the same decoder — the short forms call the long ones.

That is not duplicated code, it is one implementation with two spellings, and it is what made
moving the acceptor onto this crate a change of imports rather than a rewrite.

## Strictness

The encoder is DER, not BER: lengths are minimal, INTEGERs are minimal two's complement. This is
not pedantry — a TGS request's checksum is computed over the exact octets of `KDC-REQ-BODY`, so a
non-minimal length changes the octets the KDC hashes and no other implementation agrees.

The decoder refuses what DER refuses, including non-minimal lengths. That is a deliberate choice
over accepting a wider range: a certificate or a ticket that is not DER is not what its issuer's
signature would cover, and reading it anyway is how a parser becomes the attack surface.

## Building

The toolchain is pinned and runs in a container, so that the tests see the same OpenSSL and libc as
CI:

```sh
KDC_CARGO_VOLUME=rrl-cargo-bullseye ./scripts/cargo.sh test
```

## Licence

MIT OR Apache-2.0.
