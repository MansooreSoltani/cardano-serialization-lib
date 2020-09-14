use rand_core::{RngCore, CryptoRng};
use std::hash::Hash;
use std::fmt;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SecretKeyError {
    SizeInvalid,
    StructureInvalid,
}

impl fmt::Display for SecretKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SecretKeyError::SizeInvalid => write!(f, "Invalid Secret Key size"),
            SecretKeyError::StructureInvalid => write!(f, "Invalid Secret Key structure"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PublicKeyError {
    SizeInvalid,
    StructureInvalid,
}

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PublicKeyError::SizeInvalid => write!(f, "Invalid Public Key size"),
            PublicKeyError::StructureInvalid => write!(f, "Invalid Public Key structure"),
        }
    }
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

impl<A: AsymmetricKey> Clone for SecretKey<A> {
    fn clone(&self) -> Self {
        SecretKey(self.0.clone())
    }
}

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

impl<A: AsymmetricKey> AsRef<[u8]> for SecretKey<A> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct PublicKey<A: AsymmetricPublicKey>(pub(crate) A::Public);

impl<A: AsymmetricPublicKey> PublicKey<A> {
    pub fn from_binary(data: &[u8]) -> Result<Self, PublicKeyError> {
        Ok(PublicKey(<A as AsymmetricPublicKey>::public_from_binary(
            data,
        )?))
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

pub struct KeyPair<A: AsymmetricKey>(SecretKey<A>, PublicKey<A::PubAlg>);

impl<A: AsymmetricKey> Clone for KeyPair<A> {
    fn clone(&self) -> Self {
        KeyPair(self.0.clone(), self.1.clone())
    }
}
