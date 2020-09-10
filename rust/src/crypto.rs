use crate::chain_crypto as crypto;
use cryptoxide::blake2b::Blake2b;
use cbor_event::Serialize;
use cbor_event::se::Serializer;
use cbor_event::de::Deserializer;
use crate::serialization::{Deserialize, DeserializeError, DeserializeFailure, DeserializeEmbeddedGroup};
use crate::{to_from_bytes, to_bytes, from_bytes};
use std::io::{Write, BufRead, Seek};

// Evolving nonce type (used for Update's crypto)
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Nonce {
    hash: Option<[u8; 32]>,
}

impl Nonce {
    pub const HASH_LEN: usize = 32;
}

to_from_bytes!(Nonce);

impl Serialize for Nonce {
    fn serialize<'se, W: std::io::Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        match &self.hash {
            Some(hash) => {
                serializer.write_array(cbor_event::Len::Len(2))?;
                serializer.write_unsigned_integer(1)?;
                serializer.write_bytes(hash)
            },
            None => {
                serializer.write_array(cbor_event::Len::Len(1))?;
                serializer.write_unsigned_integer(0)
            },
        }
    }
}

impl Deserialize for Nonce {
    fn deserialize<R: std::io::BufRead>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        use std::convert::TryInto;
        (|| -> Result<Self, DeserializeError> {
            let len = raw.array()?;
            let hash = match raw.unsigned_integer()? {
                0 => None,
                1 => {
                    let bytes = raw.bytes()?;
                    if bytes.len() != Self::HASH_LEN {
                        return Err(DeserializeFailure::CBOR(cbor_event::Error::WrongLen(Self::HASH_LEN as u64, cbor_event::Len::Len(bytes.len() as u64), "hash length")).into());
                    }
                    Some(bytes[..Self::HASH_LEN].try_into().unwrap())
                },
                _ => return Err(DeserializeFailure::NoVariantMatched.into()),
            };
            match len {
                cbor_event::Len::Len(n) => {
                    let correct_len = match n {
                        1 => hash.is_none(),
                        2 => hash.is_some(),
                        _ => false,
                    };
                    if !correct_len {
                        return Err(DeserializeFailure::NoVariantMatched.into());
                    }
                },
                cbor_event::Len::Indefinite => match raw.special()? {
                    cbor_event::Special::Break => /* it's ok */(),
                    _ => return Err(DeserializeFailure::EndingBreakMissing.into()),
                },
            };
            Ok(Self {
                hash,
            })
        })().map_err(|e| e.annotate(stringify!($name)))
    }
}

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
    pub fn to_raw(&self) -> PrivateKey {
        PrivateKey(EitherEd25519SecretKey::Extended(self.0.to_raw()))
    }
    pub fn chaincode(&self) -> Vec<u8> {
        const ED25519_PRIVATE_KEY_LENGTH: usize = 64;
        const XPRV_SIZE: usize = 96;
        self.0.as_ref()[ED25519_PRIVATE_KEY_LENGTH..XPRV_SIZE].to_vec()
    }
}

pub struct PrivateKey(EitherEd25519SecretKey);

impl From<EitherEd25519SecretKey> for PrivateKey {
    fn from(secret_key: EitherEd25519SecretKey) -> PrivateKey {
        PrivateKey(secret_key)
    }
}

impl PrivateKey {
    pub fn to_public(&self) -> PublicKey {
        self.0.to_public().into()
    }
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        Ed25519Signature(self.0.sign(&message.to_vec()))
    }
}

pub struct Bip32PublicKey(crypto::PublicKey<crypto::Ed25519Bip32>);

impl Bip32PublicKey {
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
    pub fn to_raw(&self) -> PublicKey {
        PublicKey(self.0.to_raw())
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
            pub const BYTE_COUNT: usize = $byte_count;
            pub fn from_bytes(bytes: Vec<u8>) -> Result<$name, crate::serialization::DeserializeError> {
                use std::convert::TryInto;
                match bytes.len() {
                    $byte_count => Ok($name(bytes[..$byte_count].try_into().unwrap())),
                    other_len => {
                        let cbor_error = cbor_event::Error::WrongLen($byte_count, cbor_event::Len::Len(other_len as u64), "hash length");
                        Err(crate::serialization::DeserializeError::new(stringify!($name), crate::serialization::DeserializeFailure::CBOR(cbor_error)))
                    },
                }
            }
        }
        // can't expose [T; N] to wasm for new() but it's useful internally so we implement From trait
        impl From<[u8; $byte_count]> for $name {
            fn from(bytes: [u8; $byte_count]) -> Self {
                Self(bytes)
            }
        }
        impl cbor_event::se::Serialize for $name {
            fn serialize<'se, W: std::io::Write>(
                &self, serializer: &'se mut cbor_event::se::Serializer<W>
            ) -> cbor_event::Result<&'se mut cbor_event::se::Serializer<W>> {
                serializer.write_bytes(self.0)
            }
        }
        impl crate::serialization::Deserialize for $name {
            fn deserialize<R: std::io::BufRead>(
                raw: &mut cbor_event::de::Deserializer<R>
            ) -> Result<Self, crate::serialization::DeserializeError> {
                use std::convert::TryInto;
                (|| -> Result<Self, crate::serialization::DeserializeError> {
                    let bytes = raw.bytes()?;
                    if bytes.len() != $byte_count {
                        return Err(crate::serialization::DeserializeFailure::CBOR(cbor_event::Error::WrongLen($byte_count, cbor_event::Len::Len(bytes.len() as u64), "hash length")).into());
                    }
                    Ok($name(bytes[..$byte_count].try_into().unwrap()))
                })().map_err(|e| e.annotate(stringify!($name)))
            }
        }
    }
}

impl_hash_type!(Ed25519KeyHash, 28);
impl_hash_type!(ScriptHash, 28);
impl_hash_type!(TransactionHash, 32);
impl_hash_type!(GenesisDelegateHash, 28);
impl_hash_type!(GenesisHash, 28);
impl_hash_type!(MetadataHash, 32);
impl_hash_type!(VRFKeyHash, 32);

pub (crate) fn blake2b224(data: &[u8]) -> [u8; 28] {
    let mut out = [0; 28];
    Blake2b::blake2b(&mut out, data, &[]);
    out
}

pub (crate) fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    Blake2b::blake2b(&mut out, data, &[]);
    out
}

#[derive(Clone)]
pub enum EitherEd25519SecretKey {
    Extended(crypto::SecretKey<crypto::Ed25519Extended>),
    Normal(crypto::SecretKey<crypto::Ed25519>),
}

impl EitherEd25519SecretKey {
    pub fn to_public(&self) -> crypto::PublicKey<crypto::Ed25519> {
        match self {
            EitherEd25519SecretKey::Extended(sk) => sk.to_public(),
            EitherEd25519SecretKey::Normal(sk) => sk.to_public(),
        }
    }
    pub fn sign<T: AsRef<[u8]>>(&self, dat: &T) -> crypto::Signature<T, crypto::Ed25519> {
        match self {
            EitherEd25519SecretKey::Extended(sk) => sk.sign(dat),
            EitherEd25519SecretKey::Normal(sk) => sk.sign(dat),
        }
    }
}

#[derive(Clone)]
pub struct Ed25519Signature(crypto::Signature<Vec<u8>, crypto::Ed25519>);

impl cbor_event::se::Serialize for Ed25519Signature {
    fn serialize<'se, W: std::io::Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_bytes(self.0.as_ref())
    }
}

impl Deserialize for Ed25519Signature {
    fn deserialize<R: std::io::BufRead>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        Ok(Self(crypto::Signature::from_binary(raw.bytes()?.as_ref())?))
    }
}

#[derive(Clone)]
pub struct Vkey(PublicKey);

impl Vkey {
    pub fn new(pk: &PublicKey) -> Self {
        Self(pk.clone())
    }
    pub fn public_key(&self) -> PublicKey {
        self.0.clone()
    }
}

impl cbor_event::se::Serialize for Vkey {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_bytes(&self.0.as_bytes())
    }
}

impl Deserialize for Vkey {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        Ok(Self(PublicKey(crypto::PublicKey::from_binary(raw.bytes()?.as_ref())?)))
    }
}

#[derive(Clone)]
pub struct Vkeywitness {
    vkey: Vkey,
    signature: Ed25519Signature,
}

impl Vkeywitness {
    pub fn new(vkey: &Vkey, signature: &Ed25519Signature) -> Self {
        Self {
            vkey: vkey.clone(),
            signature: signature.clone()
        }
    }
}

impl cbor_event::se::Serialize for Vkeywitness {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(2))?;
        self.vkey.serialize(serializer)?;
        self.signature.serialize(serializer)
    }
}

impl Deserialize for Vkeywitness {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        (|| -> Result<_, DeserializeError> {
            let len = raw.array()?;
            let vkey = (|| -> Result<_, DeserializeError> {
                Ok(Vkey::deserialize(raw)?)
            })().map_err(|e| e.annotate("vkey"))?;
            let signature = (|| -> Result<_, DeserializeError> {
                Ok(Ed25519Signature::deserialize(raw)?)
            })().map_err(|e| e.annotate("signature"))?;
            let ret = Ok(Vkeywitness::new(&vkey, &signature));
            match len {
                cbor_event::Len::Len(n) => match n {
                    2 => (),
                    _ => return Err(DeserializeFailure::CBOR(cbor_event::Error::WrongLen(2, len, "")).into()),
                },
                cbor_event::Len::Indefinite => match raw.special()? {
                    cbor_event::Special::Break => /* it's ok */(),
                    _ => return Err(DeserializeFailure::EndingBreakMissing.into()),
                },
            }
            ret
        })().map_err(|e| e.annotate("Vkeywitness"))
    }
}

#[derive(Clone)]
pub struct Vkeywitnesses(Vec<Vkeywitness>);

impl Vkeywitnesses {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn get(&self, index: usize) -> Vkeywitness {
        self.0[index].clone()
    }
    pub fn add(&mut self, elem: &Vkeywitness) {
        self.0.push(elem.clone());
    }
}

impl cbor_event::se::Serialize for Vkeywitnesses {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(self.0.len() as u64))?;
        for element in &self.0 {
            element.serialize(serializer)?;
        }
        Ok(serializer)
    }
}

impl Deserialize for Vkeywitnesses {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        let mut arr = Vec::new();
        (|| -> Result<_, DeserializeError> {
            let len = raw.array()?;
            while match len { cbor_event::Len::Len(n) => arr.len() < n as usize, cbor_event::Len::Indefinite => true, } {
                if raw.cbor_type()? == cbor_event::Type::Special {
                    assert_eq!(raw.special()?, cbor_event::Special::Break);
                    break;
                }
                arr.push(Vkeywitness::deserialize(raw)?);
            }
            Ok(())
        })().map_err(|e| e.annotate("Vkeywitnesses"))?;
        Ok(Self(arr))
    }
}

#[derive(Clone)]
pub struct BootstrapWitness {
    vkey: Vkey,
    signature: Ed25519Signature,
    chain_code: Vec<u8>,
    attributes: Vec<u8>,
}

impl BootstrapWitness {
    pub fn new(vkey: &Vkey, signature: &Ed25519Signature, chain_code: Vec<u8>, attributes: Vec<u8>) -> Self {
        Self {
            vkey: vkey.clone(),
            signature: signature.clone(),
            chain_code: chain_code,
            attributes: attributes,
        }
    }
}

to_from_bytes!(BootstrapWitness);

impl cbor_event::se::Serialize for BootstrapWitness {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(4))?;
        self.vkey.serialize(serializer)?;
        self.signature.serialize(serializer)?;
        serializer.write_bytes(&self.chain_code)?;
        serializer.write_bytes(&self.attributes)?;
        Ok(serializer)
    }
}

impl Deserialize for BootstrapWitness {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        (|| -> Result<_, DeserializeError> {
            let len = raw.array()?;
            let ret = Self::deserialize_as_embedded_group(raw, len);
            match len {
                cbor_event::Len::Len(_) => /* TODO: check finite len somewhere */(),
                cbor_event::Len::Indefinite => match raw.special()? {
                    cbor_event::Special::Break => /* it's ok */(),
                    _ => return Err(DeserializeFailure::EndingBreakMissing.into()),
                },
            }
            ret
        })().map_err(|e| e.annotate("BootstrapWitness"))
    }
}

impl DeserializeEmbeddedGroup for BootstrapWitness {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(raw: &mut Deserializer<R>, _len: cbor_event::Len) -> Result<Self, DeserializeError> {
        let vkey = (|| -> Result<_, DeserializeError> {
            Ok(Vkey::deserialize(raw)?)
        })().map_err(|e| e.annotate("vkey"))?;
        let signature = (|| -> Result<_, DeserializeError> {
            Ok(Ed25519Signature::deserialize(raw)?)
        })().map_err(|e| e.annotate("signature"))?;
        let chain_code = (|| -> Result<_, DeserializeError> {
            Ok(raw.bytes()?)
        })().map_err(|e| e.annotate("chain_code"))?;
        let attributes = (|| -> Result<_, DeserializeError> {
            Ok(raw.bytes()?)
        })().map_err(|e| e.annotate("attributes"))?;
        Ok(BootstrapWitness {
            vkey,
            signature,
            chain_code,
            attributes,
        })
    }
}

#[derive(Clone)]
pub struct BootstrapWitnesses(Vec<BootstrapWitness>);

impl BootstrapWitnesses {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn get(&self, index: usize) -> BootstrapWitness {
        self.0[index].clone()
    }
    pub fn add(&mut self, elem: &BootstrapWitness) {
        self.0.push(elem.clone());
    }
}

impl cbor_event::se::Serialize for BootstrapWitnesses {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(self.0.len() as u64))?;
        for element in &self.0 {
            element.serialize(serializer)?;
        }
        Ok(serializer)
    }
}

impl Deserialize for BootstrapWitnesses {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        let mut arr = Vec::new();
        (|| -> Result<_, DeserializeError> {
            let len = raw.array()?;
            while match len { cbor_event::Len::Len(n) => arr.len() < n as usize, cbor_event::Len::Indefinite => true, } {
                if raw.cbor_type()? == cbor_event::Type::Special {
                    assert_eq!(raw.special()?, cbor_event::Special::Break);
                    break;
                }
                arr.push(BootstrapWitness::deserialize(raw)?);
            }
            Ok(())
        })().map_err(|e| e.annotate("BootstrapWitnesses"))?;
        Ok(Self(arr))
    }
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
