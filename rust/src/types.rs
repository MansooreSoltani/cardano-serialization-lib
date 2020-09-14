use std::io::{Write, BufRead, Seek};
use cbor_event::Serialize;
use cbor_event::se::Serializer;
use cbor_event::de::Deserializer;
use crate::serialization::{Deserialize, DeserializeError, DeserializeFailure, DeserializeEmbeddedGroup};
use crate::{to_from_bytes, to_bytes, from_bytes};

pub type Rational = UnitInterval;
pub type Epoch = u32;
pub type Slot = u32;
// index of a tx within a block
pub type TransactionIndex = u32;
// index of a cert within a tx
pub type CertificateIndex = u32;

// Specifies an amount of ADA in terms of lovelace
pub type Coin = u64;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Int(i128);

impl cbor_event::se::Serialize for Int {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        if self.0 < 0 {
            serializer.write_negative_integer((-self.0) as i64)
        } else {
            serializer.write_unsigned_integer(self.0 as u64)
        }
    }
}

impl Deserialize for Int {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        (|| -> Result<_, DeserializeError> {
            match raw.cbor_type()? {
                cbor_event::Type::UnsignedInteger => Ok(Self(raw.unsigned_integer()? as i128)),
                cbor_event::Type::NegativeInteger => Ok(Self(-raw.negative_integer()? as i128)),
                _ => Err(DeserializeFailure::NoVariantMatched.into()),
            }
        })().map_err(|e| e.annotate("Int"))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnitInterval {
    numerator: u64,
    denominator: u64,
}

impl UnitInterval {
    pub fn new(numerator: u64, denominator: u64) -> Self {
        Self {
            numerator,
            denominator,
        }
    }
    pub fn numerator(&self) -> u64 {
        self.numerator
    }
    pub fn denominator(&self) -> u64 {
        self.denominator
    }
}

to_from_bytes!(UnitInterval);

impl Serialize for UnitInterval {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_tag(30u64)?;
        serializer.write_array(cbor_event::Len::Len(2))?;
        self.numerator.serialize(serializer)?;
        self.denominator.serialize(serializer)?;
        Ok(serializer)
    }
}

impl Deserialize for UnitInterval {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        (|| -> Result<_, DeserializeError> {
            let tag = raw.tag()?;
            if tag != 30 {
                return Err(DeserializeError::new("UnitInterval", DeserializeFailure::TagMismatch{ found: tag, expected: 30 }));
            }
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
        })().map_err(|e| e.annotate("UnitInterval"))
    }
}

impl DeserializeEmbeddedGroup for UnitInterval {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(raw: &mut Deserializer<R>, _len: cbor_event::Len) -> Result<Self, DeserializeError> {
        let numerator = (|| -> Result<_, DeserializeError> {
            raw.unsigned_integer().map_err(|e| e.into())
        })().map_err(|e| e.annotate("numerator"))?;
        let denominator = (|| -> Result<_, DeserializeError> {
            raw.unsigned_integer().map_err(|e| e.into())
        })().map_err(|e| e.annotate("denominator"))?;
        Ok(UnitInterval {
            numerator,
            denominator,
        })
    }
}
