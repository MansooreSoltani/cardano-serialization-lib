use ed25519_bip32 as i;
use ed25519_bip32::{XPub, XPUB_SIZE, XPrv, XPRV_SIZE};
use rand_core::{RngCore, CryptoRng};
use crate::chain_crypto::key::{
    PublicKeyError, SecretKeyError, AsymmetricPublicKey, AsymmetricKey
};


/// Ed25519 BIP32 Signature algorithm
pub struct Ed25519Bip32;

impl From<i::PrivateKeyError> for SecretKeyError {
    fn from(v: i::PrivateKeyError) -> Self {
        match v {
            i::PrivateKeyError::HighestBitsInvalid => SecretKeyError::StructureInvalid,
            i::PrivateKeyError::LowestBitsInvalid => SecretKeyError::StructureInvalid,
            i::PrivateKeyError::LengthInvalid(_) => SecretKeyError::SizeInvalid,
        }
    }
}

impl From<i::PublicKeyError> for PublicKeyError {
    fn from(v: i::PublicKeyError) -> Self {
        match v {
            i::PublicKeyError::LengthInvalid(_) => PublicKeyError::SizeInvalid,
        }
    }
}

impl AsymmetricPublicKey for Ed25519Bip32 {
    type Public = XPub;
    const PUBLIC_BECH32_HRP: &'static str = "xpub";
    const PUBLIC_KEY_SIZE: usize = XPUB_SIZE;

    fn public_from_binary(data: &[u8]) -> Result<Self::Public, PublicKeyError> {
        let xpub = XPub::from_slice(data)?;
        Ok(xpub)
    }
}

impl AsymmetricKey for Ed25519Bip32 {
    type PubAlg = Ed25519Bip32;
    type Secret = XPrv;
    const SECRET_BECH32_HRP: &'static str = "xprv";

    fn generate<T: RngCore + CryptoRng>(mut rng: T) -> Self::Secret {
        let mut priv_bytes = [0u8; XPRV_SIZE];
        rng.fill_bytes(&mut priv_bytes);
        XPrv::normalize_bytes_force3rd(priv_bytes)
    }

    fn compute_public(secret: &Self::Secret) -> <Self as AsymmetricPublicKey>::Public {
        secret.public()
    }

    fn secret_from_binary(data: &[u8]) -> Result<Self::Secret, SecretKeyError> {
        let xprv = XPrv::from_slice_verified(data)?;
        Ok(xprv)
    }
}

