use super::*;
use std::io::{Write, BufRead};
use cbor_event::se::Serializer;
use cbor_event::de::Deserializer;
use crate::serialization::{Deserialize, DeserializeError, DeserializeFailure};

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RewardAddress {
    pub (crate) network: u8,
    pub (crate) payment: StakeCredential,
}

impl RewardAddress {
    pub fn new(network: u8, payment: &StakeCredential) -> Self {
        Self {
            network,
            payment: payment.clone(),
        }
    }

    pub fn to_address(&self) -> Address {
        Address(AddrType::Reward(self.clone()))
    }
}

// needed since we treat RewardAccount like RewardAddress
impl cbor_event::se::Serialize for RewardAddress {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        self.to_address().serialize(serializer)
    }
}

impl Deserialize for RewardAddress {
    fn deserialize<R: BufRead>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        (|| -> Result<Self, DeserializeError> {
            let bytes = raw.bytes()?;
            match Address::from_bytes_impl(bytes.as_ref())?.0 {
                AddrType::Reward(ra) => Ok(ra),
                _other_address => Err(DeserializeFailure::BadAddressType(bytes[0]).into()),
            }
        })().map_err(|e| e.annotate("RewardAddress"))
    }
}
