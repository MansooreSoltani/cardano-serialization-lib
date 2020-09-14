use crate::crypto::{Vkeywitnesses, BootstrapWitnesses};
use crate::transaction::MultisigScripts;
use cbor_event::{se::Serializer, se::Serialize, de::Deserializer};
use crate::serialization::{DeserializeError, Deserialize, DeserializeFailure, DeserializeEmbeddedGroup, Key};
use std::io::{Write, BufRead, Seek};
use crate::{to_from_bytes, to_bytes, from_bytes};

#[derive(Clone)]
pub struct TransactionWitnessSet {
    pub (crate) vkeys: Option<Vkeywitnesses>,
    pub (crate) scripts: Option<MultisigScripts>,
    pub (crate) bootstraps: Option<BootstrapWitnesses>,
}

impl TransactionWitnessSet {
    pub fn new() -> Self {
        Self {
            vkeys: None,
            scripts: None,
            bootstraps: None,
        }
    }
    pub fn vkeys(&self) -> Option<Vkeywitnesses> {
        self.vkeys.clone()
    }
    pub fn set_vkeys(&mut self, vkeys: &Vkeywitnesses) {
        self.vkeys = Some(vkeys.clone())
    }
    pub fn scripts(&self) -> Option<MultisigScripts> {
        self.scripts.clone()
    }
    pub fn set_scripts(&mut self, scripts: &MultisigScripts) {
        self.scripts = Some(scripts.clone())
    }
    pub fn bootstraps(&self) -> Option<BootstrapWitnesses> {
        self.bootstraps.clone()
    }
    pub fn set_bootstraps(&mut self, bootstraps: &BootstrapWitnesses) {
        self.bootstraps = Some(bootstraps.clone())
    }
}

to_from_bytes!(TransactionWitnessSet);

impl cbor_event::se::Serialize for TransactionWitnessSet {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_map(cbor_event::Len::Len(
            match &self.vkeys { Some(_) => 1, None => 0 }
                + match &self.scripts { Some(_) => 1, None => 0 }
                + match &self.bootstraps { Some(_) => 1, None => 0 }
        ))?;
        if let Some(field) = &self.vkeys {
            serializer.write_unsigned_integer(0)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.scripts {
            serializer.write_unsigned_integer(1)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.bootstraps {
            serializer.write_unsigned_integer(2)?;
            field.serialize(serializer)?;
        }
        Ok(serializer)
    }
}

impl Deserialize for TransactionWitnessSet {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        (|| -> Result<_, DeserializeError> {
            let len = raw.map()?;
            Self::deserialize_as_embedded_group(raw, len)
        })().map_err(|e| e.annotate("TransactionWitnessSet"))
    }
}

impl DeserializeEmbeddedGroup for TransactionWitnessSet {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(raw: &mut Deserializer<R>, len: cbor_event::Len) -> Result<Self, DeserializeError> {
        let mut vkeys = None;
        let mut scripts = None;
        let mut bootstraps = None;
        let mut read = 0;
        while match len { cbor_event::Len::Len(n) => read < n as usize, cbor_event::Len::Indefinite => true, } {
            match raw.cbor_type()? {
                cbor_event::Type::UnsignedInteger => match raw.unsigned_integer()? {
                    0 =>  {
                        if vkeys.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(0)).into());
                        }
                        vkeys = Some((|| -> Result<_, DeserializeError> {
                            Ok(Vkeywitnesses::deserialize(raw)?)
                        })().map_err(|e| e.annotate("vkeys"))?);
                    },
                    1 =>  {
                        if scripts.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(1)).into());
                        }
                        scripts = Some((|| -> Result<_, DeserializeError> {
                            Ok(MultisigScripts::deserialize(raw)?)
                        })().map_err(|e| e.annotate("scripts"))?);
                    },
                    2 =>  {
                        if bootstraps.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(2)).into());
                        }
                        bootstraps = Some((|| -> Result<_, DeserializeError> {
                            Ok(BootstrapWitnesses::deserialize(raw)?)
                        })().map_err(|e| e.annotate("bootstraps"))?);
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
        Ok(Self {
            vkeys,
            scripts,
            bootstraps,
        })
    }
}
