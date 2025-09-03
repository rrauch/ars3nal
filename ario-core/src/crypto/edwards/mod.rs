pub mod eddsa;
pub mod variants;

pub trait Curve {}

pub struct Curve25519;

impl Curve for Curve25519 {}

pub type Ed25519 = eddsa::Eddsa<Curve25519>;
pub type Ed25519SigningKey = eddsa::EddsaSigningKey<Curve25519>;
pub type Ed25519VerifyingKey = eddsa::EddsaVerifyingKey<Curve25519>;
pub type Ed25519Signature = eddsa::EddsaSignature<Curve25519>;
