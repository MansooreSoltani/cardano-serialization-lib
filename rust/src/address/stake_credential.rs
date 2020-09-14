use crate::crypto::{Ed25519KeyHash, ScriptHash};
use std::io::{Write, BufRead, Seek};
use cbor_event::Serialize;
use cbor_event::se::Serializer;
use cbor_event::de::Deserializer;
use crate::serialization::{Deserialize, DeserializeError, DeserializeFailure, Key};
use crate::{to_from_bytes, to_bytes, from_bytes};

#[derive(Debug, Clone, Hash, Eq, Ord, PartialEq, PartialOrd)]
enum StakeCredType {
    Key(Ed25519KeyHash),
    Script(ScriptHash),
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StakeCredential(StakeCredType);

to_from_bytes!(StakeCredential);

impl StakeCredential {
    pub fn from_keyhash(hash: &Ed25519KeyHash) -> Self {
        StakeCredential(StakeCredType::Key(hash.clone()))
    }
    pub fn to_keyhash(&self) -> Option<Ed25519KeyHash> {
        match &self.0 {
            StakeCredType::Key(hash) => Some(hash.clone()),
            StakeCredType::Script(_) => None,
        }
    }
    pub fn from_scripthash(hash: &ScriptHash) -> Self {
        StakeCredential(StakeCredType::Script(hash.clone()))
    }
    pub fn to_scripthash(&self) -> Option<ScriptHash> {
        match &self.0 {
            StakeCredType::Key(_) => None,
            StakeCredType::Script(hash) => Some(hash.clone()),
        }
    }
    pub fn kind(&self) -> u8 {
        match &self.0 {
            StakeCredType::Key(_) => 0,
            StakeCredType::Script(_) => 1,
        }
    }
    pub (crate) fn to_raw_bytes(&self) -> Vec<u8> {
        match &self.0 {
            StakeCredType::Key(hash) => hash.to_bytes(),
            StakeCredType::Script(hash) => hash.to_bytes(),
        }
    }
}

impl Serialize for StakeCredential {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(2))?;
        match &self.0 {
            StakeCredType::Key(keyhash) => {
                serializer.write_unsigned_integer(0u64)?;
                serializer.write_bytes(keyhash.to_bytes())
            },
            StakeCredType::Script(scripthash) => {
                serializer.write_unsigned_integer(1u64)?;
                serializer.write_bytes(scripthash.to_bytes())
            },
        }
    }
}

impl Deserialize for StakeCredential {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        (|| -> Result<_, DeserializeError> {
            let len = raw.array()?;
            if let cbor_event::Len::Len(n) = len {
                if n != 2 {
                    return Err(DeserializeFailure::CBOR(cbor_event::Error::WrongLen(2, len, "[id, hash]")).into())
                }
            }
            let cred_type = match raw.unsigned_integer()? {
                0 => StakeCredType::Key(Ed25519KeyHash::deserialize(raw)?),
                1 => StakeCredType::Script(ScriptHash::deserialize(raw)?),
                n => return Err(DeserializeFailure::FixedValueMismatch{
                    found: Key::Uint(n),
                    // TODO: change codegen to make FixedValueMismatch support Vec<Key> or ranges or something
                    expected: Key::Uint(0),
                }.into()),
            };
            if let cbor_event::Len::Indefinite = len {
                if raw.special()? != cbor_event::Special::Break {
                    return Err(DeserializeFailure::EndingBreakMissing.into());
                }
            }
            Ok(StakeCredential(cred_type))
        })().map_err(|e| e.annotate("StakeCredential"))
    }
}
