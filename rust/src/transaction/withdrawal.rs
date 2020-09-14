use crate::address::RewardAddress;
use crate::Coin;
use std::io::{Write, BufRead, Seek};
use cbor_event::Serialize;
use cbor_event::se::Serializer;
use cbor_event::de::Deserializer;
use crate::serialization::{Deserialize, DeserializeError, DeserializeFailure, Key};
use crate::{to_from_bytes, to_bytes, from_bytes};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Withdrawals(pub (crate) linked_hash_map::LinkedHashMap<RewardAddress, Coin>);

impl Withdrawals {
    pub fn new() -> Self {
        Self(linked_hash_map::LinkedHashMap::new())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn keys(&self) -> Vec<RewardAddress> {
        self.0
            .iter()
            .map(|(k, _v)| k.clone())
            .collect::<Vec<RewardAddress>>()
    }
    pub fn get(&self, key: &RewardAddress) -> Option<Coin> {
        self.0.get(key).map(|v| v.clone())
    }
    pub fn insert(&mut self, key: &RewardAddress, value: &Coin) -> Option<Coin> {
        self.0.insert(key.clone(), value.clone())
    }
    pub fn total(&self) -> Result<Coin, String> {
        self.0
            .values()
            .try_fold(
                0 as u64,
                |total: u64, &coin| {
                    match total.checked_add(coin) {
                        Some(value) => Ok(value),
                        None => Err(String::from("overflow")),
                    }
                }
            )
    }
}

to_from_bytes!(Withdrawals);

impl Serialize for Withdrawals {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_map(cbor_event::Len::Len(self.0.len() as u64))?;
        for (key, value) in &self.0 {
            key.serialize(serializer)?;
            value.serialize(serializer)?;
        }
        Ok(serializer)
    }
}

impl Deserialize for Withdrawals {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        let mut table = linked_hash_map::LinkedHashMap::new();
        (|| -> Result<_, DeserializeError> {
            let len = raw.map()?;
            while match len { cbor_event::Len::Len(n) => table.len() < n as usize, cbor_event::Len::Indefinite => true, } {
                if raw.cbor_type()? == cbor_event::Type::Special {
                    assert_eq!(raw.special()?, cbor_event::Special::Break);
                    break;
                }
                let key = RewardAddress::deserialize(raw)?;
                let value = Coin::deserialize(raw)?;
                if table.insert(key.clone(), value).is_some() {
                    return Err(DeserializeFailure::DuplicateKey(Key::Str(String::from("some complicated/unsupported type"))).into());
                }
            }
            Ok(())
        })().map_err(|e| e.annotate("Withdrawals"))?;
        Ok(Self(table))
    }
}
