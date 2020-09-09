use crate::chain_crypto as crypto;
use cryptoxide::blake2b::Blake2b;

pub struct Bip32PrivateKey(crypto::SecretKey<crypto::Ed25519Bip32>);

impl Bip32PrivateKey {
    pub fn from_bip39_entropy(entropy: &[u8], password: &[u8]) -> Self {
        Bip32PrivateKey(crypto::SecretKey::from_bip39_entropy(entropy, password))
    }
    pub fn derive(&self, index: u32) -> Self {
        Self(self.0.derive(index))
    }
    pub fn to_public(&self) -> Bip32PublicKey {
        Bip32PublicKey(self.0.to_public().into())
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
}

pub struct Bip32PublicKey(crypto::PublicKey<crypto::Ed25519Bip32>);

impl Bip32PublicKey {
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
}

impl Into<PublicKey> for Bip32PublicKey {
    fn into(self) -> PublicKey {
        PublicKey(self.0.into())
    }
}

#[derive(Clone)]
pub struct PublicKey(crypto::PublicKey<crypto::Ed25519>);

impl From<crypto::PublicKey<crypto::Ed25519>> for PublicKey {
    fn from(key: crypto::PublicKey<crypto::Ed25519>) -> PublicKey {
        PublicKey(key)
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
    pub fn hash(&self) -> Ed25519KeyHash {
        Ed25519KeyHash::from(blake2b224(self.as_bytes().as_ref()))
    }
}

macro_rules! impl_hash_type {
    ($name:ident, $byte_count:expr) => {
        #[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub (crate) [u8; $byte_count]);

        impl $name {
            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_vec()
            }
        }

        // can't expose [T; N] to wasm for new() but it's useful internally so we implement From trait
        impl From<[u8; $byte_count]> for $name {
            fn from(bytes: [u8; $byte_count]) -> Self {
                Self(bytes)
            }
        }

    }
}

impl_hash_type!(Ed25519KeyHash, 28);
impl_hash_type!(ScriptHash, 28);

pub (crate) fn blake2b224(data: &[u8]) -> [u8; 28] {
    let mut out = [0; 28];
    Blake2b::blake2b(&mut out, data, &[]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Mnemonic, Language};

    #[test]
    fn bip32_root_private_key_test() {
        let phrase = "art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let entropy = mnemonic.entropy();
        assert_eq!(entropy, [0x0c, 0xcb, 0x74, 0xf3, 0x6b, 0x7d, 0xa1, 0x64, 0x9a, 0x81, 0x44, 0x67, 0x55, 0x22, 0xd4, 0xd8, 0x09, 0x7c, 0x64, 0x12]);

        let root_key = Bip32PrivateKey::from_bip39_entropy(&entropy, &[]);
        assert_eq!(hex::encode(&root_key.as_bytes()), "b8f2bece9bdfe2b0282f5bad705562ac996efb6af96b648f4445ec44f47ad95c10e3d72f26ed075422a36ed8585c745a0e1150bcceba2357d058636991f38a3791e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4");
    }
}
