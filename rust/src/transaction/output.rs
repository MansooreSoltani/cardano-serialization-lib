use crate::address::Address;
use crate::Coin;
use std::io::{Write, BufRead, Seek};
use cbor_event::se::{Serializer, Serialize};
use cbor_event::de::Deserializer;
use crate::serialization::{Deserialize, DeserializeError, DeserializeFailure, DeserializeEmbeddedGroup};
use crate::{to_from_bytes, to_bytes, from_bytes};

#[derive(Clone, Debug)]
pub struct TransactionOutputs(pub (crate) Vec<TransactionOutput>);

impl TransactionOutputs {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn get(&self, index: usize) -> TransactionOutput {
        self.0[index].clone()
    }
    pub fn add(&mut self, elem: &TransactionOutput) {
        self.0.push(elem.clone());
    }
    pub fn total(&self) -> Result<Coin, String> {
        self.0
            .iter()
            .try_fold(
                0 as u64,
                |acc: u64, ref output| {
                    match acc.checked_add(output.amount) {
                        Some(value) => Ok(value),
                        None => Err(String::from("overflow")),
                    }
                }
            )
    }
}

to_from_bytes!(TransactionOutputs);

impl cbor_event::se::Serialize for TransactionOutputs {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(self.0.len() as u64))?;
        for element in &self.0 {
            element.serialize(serializer)?;
        }
        Ok(serializer)
    }
}

impl Deserialize for TransactionOutputs {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        let mut arr = Vec::new();
        (|| -> Result<_, DeserializeError> {
            let len = raw.array()?;
            while match len { cbor_event::Len::Len(n) => arr.len() < n as usize, cbor_event::Len::Indefinite => true, } {
                if raw.cbor_type()? == cbor_event::Type::Special {
                    assert_eq!(raw.special()?, cbor_event::Special::Break);
                    break;
                }
                arr.push(TransactionOutput::deserialize(raw)?);
            }
            Ok(())
        })().map_err(|e| e.annotate("TransactionOutputs"))?;
        Ok(Self(arr))
    }
}

#[derive(Clone, Debug)]
pub struct TransactionOutput {
    pub (crate) address: Address,
    pub (crate) amount: Coin,
}

to_from_bytes!(TransactionOutput);

impl TransactionOutput {
    pub fn new(address: &Address, amount: &Coin) -> Self {
        Self {
            address: address.clone(),
            amount: amount.clone(),
        }
    }
    pub fn address(&self) -> Address {
        self.address.clone()
    }
    pub fn amount(&self) -> Coin {
        self.amount.clone()
    }
}

impl cbor_event::se::Serialize for TransactionOutput {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(2))?;
        self.address.serialize(serializer)?;
        self.amount.serialize(serializer)?;
        Ok(serializer)
    }
}

impl Deserialize for TransactionOutput {
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
        })().map_err(|e| e.annotate("TransactionOutput"))
    }
}

impl DeserializeEmbeddedGroup for TransactionOutput {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(raw: &mut Deserializer<R>, _len: cbor_event::Len) -> Result<Self, DeserializeError> {
        let address = (|| -> Result<_, DeserializeError> {
            Ok(Address::deserialize(raw)?)
        })().map_err(|e| e.annotate("address"))?;
        let amount = (|| -> Result<_, DeserializeError> {
            Ok(Coin::deserialize(raw)?)
        })().map_err(|e| e.annotate("amount"))?;
        Ok(TransactionOutput {
            address,
            amount,
        })
    }
}

