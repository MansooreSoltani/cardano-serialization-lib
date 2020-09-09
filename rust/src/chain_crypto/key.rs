use rand_core::{RngCore, CryptoRng};
use std::hash::Hash;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SecretKeyError {
    SizeInvalid,
    StructureInvalid,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PublicKeyError {
    SizeInvalid,
    StructureInvalid,
}

pub trait AsymmetricPublicKey {
    type Public: AsRef<[u8]> + Clone + PartialEq + Eq + Hash;
    const PUBLIC_BECH32_HRP: &'static str;
    const PUBLIC_KEY_SIZE: usize;

    fn public_from_binary(data: &[u8]) -> Result<Self::Public, PublicKeyError>;
}

pub trait AsymmetricKey {
    // The name of the public key Algorithm to represent the public key
    // where PubAlg::Public is the public key type.
    type PubAlg: AsymmetricPublicKey;

    // the secret key type
    type Secret: AsRef<[u8]> + Clone;

    const SECRET_BECH32_HRP: &'static str;

    fn generate<T: RngCore + CryptoRng>(rng: T) -> Self::Secret;
    fn compute_public(secret: &Self::Secret) -> <Self::PubAlg as AsymmetricPublicKey>::Public;
    fn secret_from_binary(data: &[u8]) -> Result<Self::Secret, SecretKeyError>;
}

pub struct SecretKey<A: AsymmetricKey>(pub(crate) A::Secret);

pub struct PublicKey<A: AsymmetricPublicKey>(pub(crate) A::Public);

pub struct KeyPair<A: AsymmetricKey>(SecretKey<A>, PublicKey<A::PubAlg>);

impl<A: AsymmetricKey> SecretKey<A> {
    pub fn generate<T: RngCore + CryptoRng>(rng: T) -> Self {
        SecretKey(A::generate(rng))
    }
    pub fn to_public(&self) -> PublicKey<A::PubAlg> {
        PublicKey(<A as AsymmetricKey>::compute_public(&self.0))
    }
    pub fn from_binary(data: &[u8]) -> Result<Self, SecretKeyError> {
        Ok(SecretKey(<A as AsymmetricKey>::secret_from_binary(data)?))
    }
}

impl<A: AsymmetricKey> Clone for SecretKey<A> {
    fn clone(&self) -> Self {
        SecretKey(self.0.clone())
    }
}

impl<A: AsymmetricKey> AsRef<[u8]> for SecretKey<A> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<A: AsymmetricPublicKey> Clone for PublicKey<A> {
    fn clone(&self) -> Self {
        PublicKey(self.0.clone())
    }
}

impl<A: AsymmetricPublicKey> AsRef<[u8]> for PublicKey<A> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<A: AsymmetricKey> Clone for KeyPair<A> {
    fn clone(&self) -> Self {
        KeyPair(self.0.clone(), self.1.clone())
    }
}
