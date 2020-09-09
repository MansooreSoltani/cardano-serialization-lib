use cryptoxide::ed25519;
use ed25519_bip32::{XPrv, XPRV_SIZE};
use crate::chain_crypto::key::{AsymmetricKey, SecretKeyError, AsymmetricPublicKey};
use super::ed25519 as ei;
use rand_core::{RngCore, CryptoRng};

/// ED25519 Signing Algorithm with extended secret key
pub struct Ed25519Extended;

#[derive(Clone)]
pub struct ExtendedPriv([u8; ed25519::PRIVATE_KEY_LENGTH]);

impl AsRef<[u8]> for ExtendedPriv {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl ExtendedPriv {
    pub fn from_xprv(xprv: &XPrv) -> Self {
        let mut buf = [0; ed25519::PRIVATE_KEY_LENGTH];
        xprv.get_extended_mut(&mut buf);
        ExtendedPriv(buf)
    }
}

impl AsymmetricKey for Ed25519Extended {
    type PubAlg = ei::Ed25519;
    type Secret = ExtendedPriv;
    const SECRET_BECH32_HRP: &'static str = "ed25519e_sk";

    fn generate<T: RngCore + CryptoRng>(mut rng: T) -> Self::Secret {
        let mut priv_bytes = [0u8; XPRV_SIZE];
        rng.fill_bytes(&mut priv_bytes);
        let xprv = XPrv::normalize_bytes_force3rd(priv_bytes);

        let mut out = [0u8; ed25519::PRIVATE_KEY_LENGTH];
        xprv.get_extended_mut(&mut out);
        ExtendedPriv(out)
    }

    fn compute_public(secret: &Self::Secret) -> <Self::PubAlg as AsymmetricPublicKey>::Public {
        let pk = ed25519::to_public(&secret.0);
        ei::Pub(pk)
    }

    fn secret_from_binary(data: &[u8]) -> Result<Self::Secret, SecretKeyError> {
        if data.len() != ed25519::PRIVATE_KEY_LENGTH {
            return Err(SecretKeyError::SizeInvalid);
        }
        let mut buf = [0; ed25519::PRIVATE_KEY_LENGTH];
        buf[0..ed25519::PRIVATE_KEY_LENGTH].clone_from_slice(data);
        // TODO structure check
        Ok(ExtendedPriv(buf))
    }
}