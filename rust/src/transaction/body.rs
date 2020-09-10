use crate::crypto::{MetadataHash, TransactionHash, blake2b256};
use crate::transaction::{TransactionInputs, TransactionOutputs, Certificates, Withdrawals, Update};
use crate::{Coin};
use cbor_event::se::{Serialize, Serializer};
use cbor_event::de::Deserializer;
use crate::serialization::{Deserialize, DeserializeError, DeserializeEmbeddedGroup, DeserializeFailure, Key};
use std::io::{Write, BufRead, Seek};
use crate::{to_from_bytes, to_bytes, from_bytes};

#[derive(Clone)]
pub struct TransactionBody {
    pub (crate) inputs: TransactionInputs,
    pub (crate) outputs: TransactionOutputs,
    pub (crate) fee: Coin,
    pub (crate) ttl: u32,
    pub (crate) certs: Option<Certificates>,
    pub (crate) withdrawals: Option<Withdrawals>,
    pub (crate) update: Option<Update>,
    pub (crate) metadata_hash: Option<MetadataHash>,
}

impl TransactionBody {
    pub fn new(
        inputs: &TransactionInputs,
        outputs: &TransactionOutputs,
        fee: &Coin,
        ttl: u32,
    ) -> Self {
        Self {
            inputs: inputs.clone(),
            outputs: outputs.clone(),
            fee: fee.clone(),
            ttl: ttl,
            certs: None,
            withdrawals: None,
            update: None,
            metadata_hash: None,
        }
    }
    pub fn inputs(&self) -> TransactionInputs {
        self.inputs.clone()
    }
    pub fn outputs(&self) -> TransactionOutputs {
        self.outputs.clone()
    }
    pub fn fee(&self) -> Coin {
        self.fee.clone()
    }
    pub fn ttl(&self) -> u32 {
        self.ttl.clone()
    }
    pub fn certs(&self) -> Option<Certificates> {
        self.certs.clone()
    }
    pub fn set_certs(&mut self, certs: &Certificates) {
        self.certs = Some(certs.clone())
    }
    pub fn withdrawals(&self) -> Option<Withdrawals> {
        self.withdrawals.clone()
    }
    pub fn set_withdrawals(&mut self, withdrawals: &Withdrawals) {
        self.withdrawals = Some(withdrawals.clone())
    }
    pub fn update(&self) -> Option<Update> {
        self.update.clone()
    }
    pub fn set_update(&mut self, update: &Update) {
        self.update = Some(update.clone())
    }
    pub fn metadata_hash(&self) -> Option<MetadataHash> {
        self.metadata_hash.clone()
    }
    pub fn set_metadata_hash(&mut self, metadata_hash: &MetadataHash) {
        self.metadata_hash = Some(metadata_hash.clone())
    }
}

to_from_bytes!(TransactionBody);

impl TransactionBody {
    pub fn hash(&self) -> TransactionHash {
        TransactionHash::from(blake2b256(self.to_bytes().as_ref()))
    }
}

impl cbor_event::se::Serialize for TransactionBody {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_map(cbor_event::Len::Len(4 + match &self.certs { Some(_) => 1, None => 0 } + match &self.withdrawals { Some(_) => 1, None => 0 } + match &self.metadata_hash { Some(_) => 1, None => 0 }))?;
        serializer.write_unsigned_integer(0)?;
        self.inputs.serialize(serializer)?;
        serializer.write_unsigned_integer(1)?;
        self.outputs.serialize(serializer)?;
        serializer.write_unsigned_integer(2)?;
        self.fee.serialize(serializer)?;
        serializer.write_unsigned_integer(3)?;
        self.ttl.serialize(serializer)?;
        if let Some(field) = &self.certs {
            serializer.write_unsigned_integer(4)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.withdrawals {
            serializer.write_unsigned_integer(5)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.update {
            serializer.write_unsigned_integer(6)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.metadata_hash {
            serializer.write_unsigned_integer(7)?;
            field.serialize(serializer)?;
        }
        Ok(serializer)
    }
}

impl Deserialize for TransactionBody {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        (|| -> Result<_, DeserializeError> {
            let len = raw.map()?;
            Self::deserialize_as_embedded_group(raw, len)
        })().map_err(|e| e.annotate("TransactionBody"))
    }
}

impl DeserializeEmbeddedGroup for TransactionBody {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(raw: &mut Deserializer<R>, len: cbor_event::Len) -> Result<Self, DeserializeError> {
        let mut inputs = None;
        let mut outputs = None;
        let mut fee = None;
        let mut ttl = None;
        let mut certs = None;
        let mut withdrawals = None;
        let mut update = None;
        let mut metadata_hash = None;
        let mut read = 0;
        while match len { cbor_event::Len::Len(n) => read < n as usize, cbor_event::Len::Indefinite => true, } {
            match raw.cbor_type()? {
                cbor_event::Type::UnsignedInteger => match raw.unsigned_integer()? {
                    0 =>  {
                        if inputs.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(0)).into());
                        }
                        inputs = Some((|| -> Result<_, DeserializeError> {
                            Ok(TransactionInputs::deserialize(raw)?)
                        })().map_err(|e| e.annotate("inputs"))?);
                    },
                    1 =>  {
                        if outputs.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(1)).into());
                        }
                        outputs = Some((|| -> Result<_, DeserializeError> {
                            Ok(TransactionOutputs::deserialize(raw)?)
                        })().map_err(|e| e.annotate("outputs"))?);
                    },
                    2 =>  {
                        if fee.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(2)).into());
                        }
                        fee = Some((|| -> Result<_, DeserializeError> {
                            Ok(Coin::deserialize(raw)?)
                        })().map_err(|e| e.annotate("fee"))?);
                    },
                    3 =>  {
                        if ttl.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(3)).into());
                        }
                        ttl = Some((|| -> Result<_, DeserializeError> {
                            Ok(u32::deserialize(raw)?)
                        })().map_err(|e| e.annotate("ttl"))?);
                    },
                    4 =>  {
                        if certs.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(4)).into());
                        }
                        certs = Some((|| -> Result<_, DeserializeError> {
                            Ok(Certificates::deserialize(raw)?)
                        })().map_err(|e| e.annotate("certs"))?);
                    },
                    5 =>  {
                        if withdrawals.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(5)).into());
                        }
                        withdrawals = Some((|| -> Result<_, DeserializeError> {
                            Ok(Withdrawals::deserialize(raw)?)
                        })().map_err(|e| e.annotate("withdrawals"))?);
                    },
                    6 =>  {
                        if update.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(6)).into());
                        }
                        update = Some((|| -> Result<_, DeserializeError> {
                            Ok(Update::deserialize(raw)?)
                        })().map_err(|e| e.annotate("update"))?);
                    },
                    7 =>  {
                        if metadata_hash.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(7)).into());
                        }
                        metadata_hash = Some((|| -> Result<_, DeserializeError> {
                            Ok(MetadataHash::deserialize(raw)?)
                        })().map_err(|e| e.annotate("metadata_hash"))?);
                    },
                    unknown_key => return Err(DeserializeFailure::UnknownKey(Key::Uint(unknown_key)).into()),
                },
                cbor_event::Type::Text => match raw.text()?.as_str() {
                    unknown_key => return Err(DeserializeFailure::UnknownKey(Key::Str(unknown_key.to_owned())).into()),
                },
                cbor_event::Type::Special => match len {
                    cbor_event::Len::Len(_) => return Err(DeserializeFailure::BreakInDefiniteLen.into()),
                    cbor_event::Len::Indefinite => match raw.special()? {
                        cbor_event::Special::Break => break,
                        _ => return Err(DeserializeFailure::EndingBreakMissing.into()),
                    },
                },
                other_type => return Err(DeserializeFailure::UnexpectedKeyType(other_type).into()),
            }
            read += 1;
        }
        let inputs = match inputs {
            Some(x) => x,
            None => return Err(DeserializeFailure::MandatoryFieldMissing(Key::Uint(0)).into()),
        };
        let outputs = match outputs {
            Some(x) => x,
            None => return Err(DeserializeFailure::MandatoryFieldMissing(Key::Uint(1)).into()),
        };
        let fee = match fee {
            Some(x) => x,
            None => return Err(DeserializeFailure::MandatoryFieldMissing(Key::Uint(2)).into()),
        };
        let ttl = match ttl {
            Some(x) => x,
            None => return Err(DeserializeFailure::MandatoryFieldMissing(Key::Uint(3)).into()),
        };
        Ok(Self {
            inputs,
            outputs,
            fee,
            ttl,
            certs,
            withdrawals,
            update,
            metadata_hash,
        })
    }
}
