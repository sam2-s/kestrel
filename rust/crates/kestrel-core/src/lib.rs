//! Protocol v2 for Kestrel: wire format, cryptography, and the client state
//! machine. This crate holds every constant and every derivation in the
//! protocol, and it is shared verbatim by the app and the relay so the two
//! cannot drift apart.
//!
//! Interoperability note. Kestrel implements the same wire protocol as
//! Starling v2, so a circle, a relay and an invite all interoperate with that
//! implementation. The derivations are reproduced from the published protocol
//! document and verified byte-for-byte against its committed test vectors;
//! see `tests/vectors.rs` and `docs/INTEROP.md`.

pub mod b64;
pub mod beacon;
pub mod geo;
pub mod identity;
pub mod invite;
pub mod kdf;
pub mod membership;
pub mod msg;
pub mod places;
pub mod ratchet;
pub mod rekey;
pub mod roster;
pub mod seal;
pub mod session;
pub mod vault;
pub mod wire;

/// The protocol tag this build speaks. Prefixes every derivation and appears in
/// both the associated data and the signed string.
pub use kdf::PROTO;

/// The group order of P-256, minus one. A private scalar must be strictly
/// below this; `identity` compares against it in constant time.
pub const P256_ORDER_HIGH: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
    0xfc, 0x63, 0x25, 0x51,
];
