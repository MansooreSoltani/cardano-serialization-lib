use cbor_event::{se::Serializer, se::Serialize, de::Deserializer};
use crate::serialization::{DeserializeError, Deserialize, DeserializeFailure, DeserializeEmbeddedGroup};
use crate::transaction::{TransactionBody, TransactionWitnessSet, TransactionMetadata};
use std::io::{Write, BufRead, Seek};
use crate::{to_from_bytes, to_bytes, from_bytes};

#[derive(Clone)]
pub struct Transaction {
    pub (crate) body: TransactionBody,
    pub (crate) witness_set: TransactionWitnessSet,
    pub (crate) metadata: Option<TransactionMetadata>,
}

to_from_bytes!(Transaction);

impl cbor_event::se::Serialize for Transaction {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(3))?;
        self.body.serialize(serializer)?;
        self.witness_set.serialize(serializer)?;
        match &self.metadata {
            Some(x) => {
                x.serialize(serializer)
            },
            None => serializer.write_special(cbor_event::Special::Null),
        }?;
        Ok(serializer)
    }
}

impl Deserialize for Transaction {
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
        })().map_err(|e| e.annotate("Transaction"))
    }
}

impl DeserializeEmbeddedGroup for Transaction {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(raw: &mut Deserializer<R>, _len: cbor_event::Len) -> Result<Self, DeserializeError> {
        let body = (|| -> Result<_, DeserializeError> {
            Ok(TransactionBody::deserialize(raw)?)
        })().map_err(|e| e.annotate("body"))?;
        let witness_set = (|| -> Result<_, DeserializeError> {
            Ok(TransactionWitnessSet::deserialize(raw)?)
        })().map_err(|e| e.annotate("witness_set"))?;
        let metadata = (|| -> Result<_, DeserializeError> {
            Ok(match raw.cbor_type()? != cbor_event::Type::Special {
                true => {
                    Some(TransactionMetadata::deserialize(raw)?)
                },
                false => {
                    if raw.special()? != cbor_event::Special::Null {
                        return Err(DeserializeFailure::ExpectedNull.into());
                    }
                    None
                }
            })
        })().map_err(|e| e.annotate("metadata"))?;
        Ok(Transaction {
            body,
            witness_set,
            metadata,
        })
    }
}
