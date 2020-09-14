use crate::{Epoch, Coin, Rational, UnitInterval};
use crate::crypto::{GenesisHash, Nonce};
use std::io::{Write, BufRead, Seek};
use cbor_event::Serialize;
use cbor_event::se::Serializer;
use cbor_event::de::Deserializer;
use crate::serialization::{Deserialize, DeserializeError, DeserializeFailure, DeserializeEmbeddedGroup, Key, SerializeEmbeddedGroup};
use crate::{to_from_bytes, to_bytes, from_bytes};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Update {
    proposed_protocol_parameter_updates: ProposedProtocolParameterUpdates,
    epoch: Epoch,
}

to_from_bytes!(Update);

impl cbor_event::se::Serialize for Update {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(2))?;
        self.proposed_protocol_parameter_updates.serialize(serializer)?;
        self.epoch.serialize(serializer)?;
        Ok(serializer)
    }
}

impl Deserialize for Update {
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
        })().map_err(|e| e.annotate("Update"))
    }
}

impl DeserializeEmbeddedGroup for Update {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(raw: &mut Deserializer<R>, _len: cbor_event::Len) -> Result<Self, DeserializeError> {
        let proposed_protocol_parameter_updates = (|| -> Result<_, DeserializeError> {
            Ok(ProposedProtocolParameterUpdates::deserialize(raw)?)
        })().map_err(|e| e.annotate("proposed_protocol_parameter_updates"))?;
        let epoch = (|| -> Result<_, DeserializeError> {
            Ok(Epoch::deserialize(raw)?)
        })().map_err(|e| e.annotate("epoch"))?;
        Ok(Update {
            proposed_protocol_parameter_updates,
            epoch,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProposedProtocolParameterUpdates(
    linked_hash_map::LinkedHashMap<GenesisHash, ProtocolParamUpdate>,
);

to_from_bytes!(ProposedProtocolParameterUpdates);

impl cbor_event::se::Serialize for ProposedProtocolParameterUpdates {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_map(cbor_event::Len::Len(self.0.len() as u64))?;
        for (key, value) in &self.0 {
            key.serialize(serializer)?;
            value.serialize(serializer)?;
        }
        Ok(serializer)
    }
}

impl Deserialize for ProposedProtocolParameterUpdates {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        let mut table = linked_hash_map::LinkedHashMap::new();
        (|| -> Result<_, DeserializeError> {
            let len = raw.map()?;
            while match len { cbor_event::Len::Len(n) => table.len() < n as usize, cbor_event::Len::Indefinite => true, } {
                if raw.cbor_type()? == cbor_event::Type::Special {
                    assert_eq!(raw.special()?, cbor_event::Special::Break);
                    break;
                }
                let key = GenesisHash::deserialize(raw)?;
                let value = ProtocolParamUpdate::deserialize(raw)?;
                if table.insert(key.clone(), value).is_some() {
                    return Err(DeserializeFailure::DuplicateKey(Key::Str(String::from("some complicated/unsupported type"))).into());
                }
            }
            Ok(())
        })().map_err(|e| e.annotate("ProposedProtocolParameterUpdates"))?;
        Ok(Self(table))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolParamUpdate {
    minfee_a: Option<Coin>,
    minfee_b: Option<Coin>,
    max_block_body_size: Option<u32>,
    max_tx_size: Option<u32>,
    max_block_header_size: Option<u32>,
    key_deposit: Option<Coin>,
    pool_deposit: Option<Coin>,
    max_epoch: Option<Epoch>,
    // desired number of stake pools
    n_opt: Option<u32>,
    pool_pledge_influence: Option<Rational>,
    expansion_rate: Option<UnitInterval>,
    treasury_growth_rate: Option<UnitInterval>,
    // decentralization constant
    d: Option<UnitInterval>,
    extra_entropy: Option<Nonce>,
    protocol_version: Option<ProtocolVersions>,
    min_utxo_value: Option<Coin>,
}

to_from_bytes!(ProtocolParamUpdate);

impl cbor_event::se::Serialize for ProtocolParamUpdate {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_map(cbor_event::Len::Len(match &self.minfee_a { Some(_) => 1, None => 0 } + match &self.minfee_b { Some(_) => 1, None => 0 } + match &self.max_block_body_size { Some(_) => 1, None => 0 } + match &self.max_tx_size { Some(_) => 1, None => 0 } + match &self.max_block_header_size { Some(_) => 1, None => 0 } + match &self.key_deposit { Some(_) => 1, None => 0 } + match &self.pool_deposit { Some(_) => 1, None => 0 } + match &self.max_epoch { Some(_) => 1, None => 0 } + match &self.n_opt { Some(_) => 1, None => 0 } + match &self.pool_pledge_influence { Some(_) => 1, None => 0 } + match &self.expansion_rate { Some(_) => 1, None => 0 } + match &self.treasury_growth_rate { Some(_) => 1, None => 0 } + match &self.d { Some(_) => 1, None => 0 } + match &self.extra_entropy { Some(_) => 1, None => 0 } + match &self.protocol_version { Some(_) => 1, None => 0 } + match &self.min_utxo_value { Some(_) => 1, None => 0 }))?;
        if let Some(field) = &self.minfee_a {
            serializer.write_unsigned_integer(0)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.minfee_b {
            serializer.write_unsigned_integer(1)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.max_block_body_size {
            serializer.write_unsigned_integer(2)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.max_tx_size {
            serializer.write_unsigned_integer(3)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.max_block_header_size {
            serializer.write_unsigned_integer(4)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.key_deposit {
            serializer.write_unsigned_integer(5)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.pool_deposit {
            serializer.write_unsigned_integer(6)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.max_epoch {
            serializer.write_unsigned_integer(7)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.n_opt {
            serializer.write_unsigned_integer(8)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.pool_pledge_influence {
            serializer.write_unsigned_integer(9)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.expansion_rate {
            serializer.write_unsigned_integer(10)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.treasury_growth_rate {
            serializer.write_unsigned_integer(11)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.d {
            serializer.write_unsigned_integer(12)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.extra_entropy {
            serializer.write_unsigned_integer(13)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.protocol_version {
            serializer.write_unsigned_integer(14)?;
            field.serialize(serializer)?;
        }
        if let Some(field) = &self.min_utxo_value {
            serializer.write_unsigned_integer(15)?;
            field.serialize(serializer)?;
        }
        Ok(serializer)
    }
}

impl Deserialize for ProtocolParamUpdate {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        (|| -> Result<_, DeserializeError> {
            let len = raw.map()?;
            Self::deserialize_as_embedded_group(raw, len)
        })().map_err(|e| e.annotate("ProtocolParamUpdate"))
    }
}

impl DeserializeEmbeddedGroup for ProtocolParamUpdate {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(raw: &mut Deserializer<R>, len: cbor_event::Len) -> Result<Self, DeserializeError> {
        let mut minfee_a = None;
        let mut minfee_b = None;
        let mut max_block_body_size = None;
        let mut max_tx_size = None;
        let mut max_block_header_size = None;
        let mut key_deposit = None;
        let mut pool_deposit = None;
        let mut max_epoch = None;
        let mut n_opt = None;
        let mut pool_pledge_influence = None;
        let mut expansion_rate = None;
        let mut treasury_growth_rate = None;
        let mut d = None;
        let mut extra_entropy = None;
        let mut protocol_version = None;
        let mut min_utxo_value = None;
        let mut read = 0;
        while match len { cbor_event::Len::Len(n) => read < n as usize, cbor_event::Len::Indefinite => true, } {
            match raw.cbor_type()? {
                cbor_event::Type::UnsignedInteger => match raw.unsigned_integer()? {
                    0 =>  {
                        if minfee_a.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(0)).into());
                        }
                        minfee_a = Some((|| -> Result<_, DeserializeError> {
                            Ok(Coin::deserialize(raw)?)
                        })().map_err(|e| e.annotate("minfee_a"))?);
                    },
                    1 =>  {
                        if minfee_b.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(1)).into());
                        }
                        minfee_b = Some((|| -> Result<_, DeserializeError> {
                            Ok(Coin::deserialize(raw)?)
                        })().map_err(|e| e.annotate("minfee_b"))?);
                    },
                    2 =>  {
                        if max_block_body_size.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(2)).into());
                        }
                        max_block_body_size = Some((|| -> Result<_, DeserializeError> {
                            Ok(u32::deserialize(raw)?)
                        })().map_err(|e| e.annotate("max_block_body_size"))?);
                    },
                    3 =>  {
                        if max_tx_size.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(3)).into());
                        }
                        max_tx_size = Some((|| -> Result<_, DeserializeError> {
                            Ok(u32::deserialize(raw)?)
                        })().map_err(|e| e.annotate("max_tx_size"))?);
                    },
                    4 =>  {
                        if max_block_header_size.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(4)).into());
                        }
                        max_block_header_size = Some((|| -> Result<_, DeserializeError> {
                            Ok(u32::deserialize(raw)?)
                        })().map_err(|e| e.annotate("max_block_header_size"))?);
                    },
                    5 =>  {
                        if key_deposit.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(5)).into());
                        }
                        key_deposit = Some((|| -> Result<_, DeserializeError> {
                            Ok(Coin::deserialize(raw)?)
                        })().map_err(|e| e.annotate("key_deposit"))?);
                    },
                    6 =>  {
                        if pool_deposit.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(6)).into());
                        }
                        pool_deposit = Some((|| -> Result<_, DeserializeError> {
                            Ok(Coin::deserialize(raw)?)
                        })().map_err(|e| e.annotate("pool_deposit"))?);
                    },
                    7 =>  {
                        if max_epoch.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(7)).into());
                        }
                        max_epoch = Some((|| -> Result<_, DeserializeError> {
                            Ok(Epoch::deserialize(raw)?)
                        })().map_err(|e| e.annotate("max_epoch"))?);
                    },
                    8 =>  {
                        if n_opt.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(8)).into());
                        }
                        n_opt = Some((|| -> Result<_, DeserializeError> {
                            Ok(u32::deserialize(raw)?)
                        })().map_err(|e| e.annotate("n_opt"))?);
                    },
                    9 =>  {
                        if pool_pledge_influence.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(9)).into());
                        }
                        pool_pledge_influence = Some((|| -> Result<_, DeserializeError> {
                            Ok(Rational::deserialize(raw)?)
                        })().map_err(|e| e.annotate("pool_pledge_influence"))?);
                    },
                    10 =>  {
                        if expansion_rate.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(10)).into());
                        }
                        expansion_rate = Some((|| -> Result<_, DeserializeError> {
                            Ok(UnitInterval::deserialize(raw)?)
                        })().map_err(|e| e.annotate("expansion_rate"))?);
                    },
                    11 =>  {
                        if treasury_growth_rate.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(11)).into());
                        }
                        treasury_growth_rate = Some((|| -> Result<_, DeserializeError> {
                            Ok(UnitInterval::deserialize(raw)?)
                        })().map_err(|e| e.annotate("treasury_growth_rate"))?);
                    },
                    12 =>  {
                        if d.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(12)).into());
                        }
                        d = Some((|| -> Result<_, DeserializeError> {
                            Ok(UnitInterval::deserialize(raw)?)
                        })().map_err(|e| e.annotate("d"))?);
                    },
                    13 =>  {
                        if extra_entropy.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(13)).into());
                        }
                        extra_entropy = Some((|| -> Result<_, DeserializeError> {
                            Ok(Nonce::deserialize(raw)?)
                        })().map_err(|e| e.annotate("extra_entropy"))?);
                    },
                    14 =>  {
                        if protocol_version.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(14)).into());
                        }
                        protocol_version = Some((|| -> Result<_, DeserializeError> {
                            Ok(ProtocolVersions::deserialize(raw)?)
                        })().map_err(|e| e.annotate("protocol_version"))?);
                    },
                    15 =>  {
                        if min_utxo_value.is_some() {
                            return Err(DeserializeFailure::DuplicateKey(Key::Uint(15)).into());
                        }
                        min_utxo_value = Some((|| -> Result<_, DeserializeError> {
                            Ok(Coin::deserialize(raw)?)
                        })().map_err(|e| e.annotate("min_utxo_value"))?);
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
            minfee_a,
            minfee_b,
            max_block_body_size,
            max_tx_size,
            max_block_header_size,
            key_deposit,
            pool_deposit,
            max_epoch,
            n_opt,
            pool_pledge_influence,
            expansion_rate,
            treasury_growth_rate,
            d,
            extra_entropy,
            protocol_version,
            min_utxo_value,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersions(Vec<ProtocolVersion>);

impl ProtocolVersions {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get(&self, index: usize) -> ProtocolVersion {
        self.0[index].clone()
    }

    pub fn add(&mut self, elem: &ProtocolVersion) {
        self.0.push(elem.clone());
    }
}

to_from_bytes!(ProtocolVersions);

impl cbor_event::se::Serialize for ProtocolVersions {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(self.0.len() as u64))?;
        for element in &self.0 {
            element.serialize_as_embedded_group(serializer)?;
        }
        Ok(serializer)
    }
}

impl Deserialize for ProtocolVersions {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        let mut arr = Vec::new();
        (|| -> Result<_, DeserializeError> {
            let len = raw.array()?;
            while match len { cbor_event::Len::Len(n) => arr.len() < n as usize, cbor_event::Len::Indefinite => true, } {
                if raw.cbor_type()? == cbor_event::Type::Special {
                    assert_eq!(raw.special()?, cbor_event::Special::Break);
                    break;
                }
                arr.push(ProtocolVersion::deserialize_as_embedded_group(raw, len)?);
            }
            Ok(())
        })().map_err(|e| e.annotate("ProtocolVersions"))?;
        Ok(Self(arr))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    major: u32,
    minor: u32,
}

impl ProtocolVersion {
    pub fn major(&self) -> u32 {
        self.major
    }

    pub fn minor(&self) -> u32 {
        self.minor
    }

    pub fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }
}

to_from_bytes!(ProtocolVersion);

impl cbor_event::se::Serialize for ProtocolVersion {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(2))?;
        self.serialize_as_embedded_group(serializer)
    }
}

impl SerializeEmbeddedGroup for ProtocolVersion {
    fn serialize_as_embedded_group<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        self.major.serialize(serializer)?;
        self.minor.serialize(serializer)?;
        Ok(serializer)
    }
}

impl Deserialize for ProtocolVersion {
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
        })().map_err(|e| e.annotate("ProtocolVersion"))
    }
}

impl DeserializeEmbeddedGroup for ProtocolVersion {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(raw: &mut Deserializer<R>, _len: cbor_event::Len) -> Result<Self, DeserializeError> {
        let major = (|| -> Result<_, DeserializeError> {
            Ok(u32::deserialize(raw)?)
        })().map_err(|e| e.annotate("major"))?;
        let minor = (|| -> Result<_, DeserializeError> {
            Ok(u32::deserialize(raw)?)
        })().map_err(|e| e.annotate("minor"))?;
        Ok(ProtocolVersion {
            major,
            minor,
        })
    }
}
