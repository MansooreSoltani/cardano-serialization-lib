use crate::chain_crypto;
use std::io::{BufRead, Seek, Write};
use cbor_event::de::Deserializer;
use cbor_event::se::Serializer;

#[derive(Debug)]
pub enum Key {
    Str(String),
    Uint(u64),
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Str(x) => write!(f, "\"{}\"", x),
            Key::Uint(x) => write!(f, "{}", x),
        }
    }
}

#[derive(Debug)]
pub enum DeserializeFailure {
    BadAddressType(u8),
    BreakInDefiniteLen,
    CBOR(cbor_event::Error),
    DuplicateKey(Key),
    EndingBreakMissing,
    ExpectedNull,
    FixedValueMismatch{
        found: Key,
        expected: Key,
    },
    MandatoryFieldMissing(Key),
    NoVariantMatched,
    PublicKeyError(chain_crypto::PublicKeyError),
    SignatureError(chain_crypto::SignatureError),
    TagMismatch{
        found: u64,
        expected: u64,
    },
    UnknownKey(Key),
    UnexpectedKeyType(cbor_event::Type),
    VariableLenNatDecodeFailed,
}

#[derive(Debug)]
pub struct DeserializeError {
    location: Option<String>,
    failure: DeserializeFailure,
}

impl DeserializeError {
    pub fn new<T: Into<String>>(location: T, failure: DeserializeFailure) -> Self {
        Self {
            location: Some(location.into()),
            failure,
        }
    }

    pub fn annotate<T: Into<String>>(self, location: T) -> Self {
        match self.location {
            Some(loc) => Self::new(format!("{}.{}", location.into(), loc), self.failure),
            None => Self::new(location, self.failure),
        }
    }
}

impl std::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.location {
            Some(loc) => write!(f, "Deserialization failed in {} because: ", loc),
            None => write!(f, "Deserialization: "),
        }?;
        match &self.failure {
            DeserializeFailure::BadAddressType(header) => write!(f, "Encountered unknown address header {:#08b}", header),
            DeserializeFailure::BreakInDefiniteLen => write!(f, "Encountered CBOR Break while reading definite length sequence"),
            DeserializeFailure::CBOR(e) => e.fmt(f),
            DeserializeFailure::DuplicateKey(key) => write!(f, "Duplicate key: {}", key),
            DeserializeFailure::EndingBreakMissing => write!(f, "Missing ending CBOR Break"),
            DeserializeFailure::ExpectedNull => write!(f, "Expected null, found other type"),
            DeserializeFailure::FixedValueMismatch{ found, expected } => write!(f, "Expected fixed value {} found {}", expected, found),
            DeserializeFailure::MandatoryFieldMissing(key) => write!(f, "Mandatory field {} not found", key),
            DeserializeFailure::NoVariantMatched => write!(f, "No variant matched"),
            DeserializeFailure::PublicKeyError(e) => write!(f, "PublicKeyError error: {}", e),
            DeserializeFailure::SignatureError(e) => write!(f, "Signature error: {}", e),
            DeserializeFailure::TagMismatch{ found, expected } => write!(f, "Expected tag {}, found {}", expected, found),
            DeserializeFailure::UnknownKey(key) => write!(f, "Found unexpected key {}", key),
            DeserializeFailure::UnexpectedKeyType(ty) => write!(f, "Found unexpected key of CBOR type {:?}", ty),
            DeserializeFailure::VariableLenNatDecodeFailed => write!(f, "Variable length natural number decode failed"),
        }
    }
}

impl From<DeserializeFailure> for DeserializeError {
    fn from(failure: DeserializeFailure) -> DeserializeError {
        DeserializeError {
            location: None,
            failure,
        }
    }
}

impl From<cbor_event::Error> for DeserializeError {
    fn from(err: cbor_event::Error) -> DeserializeError {
        DeserializeError {
            location: None,
            failure: DeserializeFailure::CBOR(err),
        }
    }
}

impl From<chain_crypto::SignatureError> for DeserializeError {
    fn from(err: chain_crypto::SignatureError) -> DeserializeError {
        DeserializeError {
            location: None,
            failure: DeserializeFailure::SignatureError(err),
        }
    }
}

impl From<chain_crypto::PublicKeyError> for DeserializeError {
    fn from(err: chain_crypto::PublicKeyError) -> DeserializeError {
        DeserializeError {
            location: None,
            failure: DeserializeFailure::PublicKeyError(err),
        }
    }
}

// same as cbor_event::de::Deserialize but with our DeserializeError
pub trait Deserialize {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> where Self: Sized;
}

// auto-implement for all cbor_event Deserialize implementors
impl<T: cbor_event::de::Deserialize> Deserialize for T {
    fn deserialize<R: BufRead + Seek>(raw: &mut Deserializer<R>) -> Result<T, DeserializeError> {
        T::deserialize(raw).map_err(|e| DeserializeError::from(e))
    }
}

// This is only for use for plain cddl groups who need to be embedded within outer groups.
pub trait DeserializeEmbeddedGroup {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(
        raw: &mut Deserializer<R>,
        len: cbor_event::Len,
    ) -> Result<Self, DeserializeError> where Self: Sized;
}

// This is only for use for plain cddl groups who need to be embedded within outer groups.
pub (crate) trait SerializeEmbeddedGroup {
    fn serialize_as_embedded_group<'a, W: Write + Sized>(
        &self,
        serializer: &'a mut Serializer<W>,
    ) -> cbor_event::Result<&'a mut Serializer<W>>;
}

#[macro_export]
macro_rules! from_bytes {
    // Custom from_bytes() code
    ($name:ident, $data:ident, $body:block) => {
        impl $name {
            pub fn from_bytes($data: Vec<u8>) -> Result<$name, crate::serialization::DeserializeError> $body
        }
    };
    // Uses Deserialize trait to auto-generate one
    ($name:ident) => {
        from_bytes!($name, bytes, {
            let mut raw = cbor_event::de::Deserializer::from(std::io::Cursor::new(bytes));
            Self::deserialize(&mut raw)
        });
    };
}

#[macro_export]
macro_rules! to_bytes {
    ($name:ident) => {
        impl $name {
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut buf = cbor_event::se::Serializer::new_vec();
                self.serialize(&mut buf).unwrap();
                buf.finalize()
            }
        }
    }
}

#[macro_export]
macro_rules! to_from_bytes {
    ($name:ident) => {
        to_bytes!($name);
        from_bytes!($name);
    }
}
