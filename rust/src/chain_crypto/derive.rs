use cryptoxide::hmac::Hmac;
use cryptoxide::pbkdf2::pbkdf2;
use cryptoxide::sha2::Sha512;
use ed25519_bip32 as i;
use ed25519_bip32::{XPrv, DerivationScheme, XPRV_SIZE};
use crate::chain_crypto::key::{PublicKey, SecretKey};
use crate::chain_crypto::algorithms::{Ed25519Bip32, ed25519_extended::ExtendedPriv, ed25519::Pub};
use crate::chain_crypto::{Ed25519Extended, Ed25519};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DerivationError {
    InvalidAddition,
    ExpectedSoftDerivation,
}

impl From<i::DerivationError> for DerivationError {
    fn from(v: i::DerivationError) -> Self {
        match v {
            i::DerivationError::InvalidAddition => DerivationError::InvalidAddition,
            i::DerivationError::ExpectedSoftDerivation => DerivationError::ExpectedSoftDerivation,
        }
    }
}

impl SecretKey<Ed25519Bip32> {
    pub fn from_bip39_entropy(entropy: &[u8], password: &[u8]) -> Self {
        let mut pbkdf2_result = [0; XPRV_SIZE];
        const ITER: u32 = 4096;
        let mut mac = Hmac::new(Sha512::new(), password);
        pbkdf2(&mut mac, entropy.as_ref(), ITER, &mut pbkdf2_result);
        SecretKey(XPrv::normalize_bytes_force3rd(pbkdf2_result))
    }
    pub fn derive(&self, index: u32) -> Self {
        let derived_private_key = self.0.derive(DerivationScheme::V2, index);
        SecretKey(derived_private_key)
    }
}

impl Into<SecretKey<Ed25519Extended>> for SecretKey<Ed25519Bip32> {
    fn into(self) -> SecretKey<Ed25519Extended> {
        SecretKey(ExtendedPriv::from_xprv(&self.0))
    }
}

impl PublicKey<Ed25519Bip32> {
    pub fn derive(&self, index: u32) -> Result<Self, DerivationError> {
        let derived_public_key = self.0.derive(DerivationScheme::V2, index)?;
        Ok(PublicKey(derived_public_key))
    }
}

impl Into<PublicKey<Ed25519>> for PublicKey<Ed25519Bip32> {
    fn into(self) -> PublicKey<Ed25519> {
        PublicKey(Pub::from_xpub(&self.0))
    }
}
