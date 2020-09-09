use crate::crypto::{Ed25519KeyHash, ScriptHash};

#[derive(Debug, Clone, Hash, Eq, Ord, PartialEq, PartialOrd)]
enum StakeCredType {
    Key(Ed25519KeyHash),
    Script(ScriptHash),
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StakeCredential(StakeCredType);

impl StakeCredential {
    pub fn from_keyhash(hash: &Ed25519KeyHash) -> Self {
        StakeCredential(StakeCredType::Key(hash.clone()))
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