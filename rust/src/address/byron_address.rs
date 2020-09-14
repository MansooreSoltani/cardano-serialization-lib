use cbor_event::cbor;
use cbor_event::de::Deserializer;
use cbor_event::se::{Serializer, Serialize};
use crate::serialization::Deserialize;
use std::io::{Write, BufRead};
use std::fmt;
use std::convert::TryInto;
use crate::crypto::Bip32PublicKey;
use ed25519_bip32::XPub;
use cryptoxide::sha3;
use cryptoxide::digest::Digest;
use cryptoxide::blake2b::Blake2b;
use super::*;


const EXTENDED_ADDR_LEN: usize = 28;

type HDAddressPayload = Vec<u8>;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Attributes {
    pub derivation_path: Option<HDAddressPayload>,
    pub network_magic: Option<u32>,
}

impl Attributes {
    pub fn new_bootstrap_era(hdap: Option<HDAddressPayload>, network_magic: Option<u32>) -> Self {
        Attributes {
            derivation_path: hdap,
            network_magic,
        }
    }
}

const ATTRIBUTE_NAME_TAG_DERIVATION: u64 = 1;
const ATTRIBUTE_NAME_TAG_NETWORK_MAGIC: u64 = 2;

impl cbor_event::se::Serialize for Attributes {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        let mut len = 0;
        if let Some(_) = &self.derivation_path {
            len += 1
        };
        if let Some(_) = &self.network_magic {
            len += 1
        };
        let serializer = serializer.write_map(cbor_event::Len::Len(len))?;
        let serializer = match &self.derivation_path {
            &None => serializer,
            &Some(ref dp) => serializer
                .write_unsigned_integer(ATTRIBUTE_NAME_TAG_DERIVATION)?
                .write_bytes(&dp)?,
        };
        let serializer = match &self.network_magic {
            &None => serializer,
            &Some(network_magic) => serializer
                .write_unsigned_integer(ATTRIBUTE_NAME_TAG_NETWORK_MAGIC)?
                .write_bytes(cbor!(&network_magic)?)?,
        };
        Ok(serializer)
    }
}

impl cbor_event::de::Deserialize for Attributes {
    fn deserialize<R: BufRead>(reader: &mut Deserializer<R>) -> cbor_event::Result<Self> {
        let len = reader.map()?;
        let mut len = match len {
            cbor_event::Len::Indefinite => {
                return Err(cbor_event::Error::CustomError(format!(
                    "Invalid Attributes: received map of {:?} elements",
                    len
                )));
            }
            cbor_event::Len::Len(len) => len,
        };
        let mut derivation_path = None;
        let mut network_magic = None;
        while len > 0 {
            let key = reader.unsigned_integer()?;
            match key {
                ATTRIBUTE_NAME_TAG_DERIVATION => derivation_path = Some(reader.bytes()?),
                ATTRIBUTE_NAME_TAG_NETWORK_MAGIC => {
                    // Yes, this is an integer encoded as CBOR encoded as Bytes in CBOR.
                    let bytes = reader.bytes()?;
                    let n = Deserializer::from(std::io::Cursor::new(bytes)).deserialize::<u32>()?;
                    network_magic = Some(n);
                }
                _ => {
                    return Err(cbor_event::Error::CustomError(format!(
                        "invalid Attribute key {}",
                        key
                    )));
                }
            }
            len -= 1;
        }
        Ok(Attributes {
            derivation_path,
            network_magic,
        })
    }
}

// public key tag only for encoding/decoding purpose
struct PubKeyTag();

impl cbor_event::se::Serialize for PubKeyTag {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_unsigned_integer(0)
    }
}

impl cbor_event::de::Deserialize for PubKeyTag {
    fn deserialize<R: BufRead>(reader: &mut Deserializer<R>) -> cbor_event::Result<Self> {
        match reader.unsigned_integer()? {
            0 => Ok(PubKeyTag()),
            _ => Err(cbor_event::Error::CustomError(format!("Invalid AddrType"))),
        }
    }
}

const SPENDING_DATA_TAG_PUBKEY: u64 = 0;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpendingData<'a>(&'a XPub);

impl<'a> cbor_event::se::Serialize for SpendingData<'a> {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        let ar: [u8; 64] = self.0.clone().into();
        serializer
            .write_array(cbor_event::Len::Len(2))?
            .write_unsigned_integer(SPENDING_DATA_TAG_PUBKEY)?
            .write_bytes(&ar[..])
    }
}

#[derive(Clone, Debug)]
pub struct ByronAddress {
    pub addr: [u8; EXTENDED_ADDR_LEN],
    pub attributes: Attributes,
}

impl ByronAddress {
    pub fn new(xpub: &XPub, attrs: Attributes) -> Self {
        Self {
            addr: hash_spending_data(xpub, &attrs),
            attributes: attrs,
        }
    }
    pub fn new_simple(xpub: &XPub, network_magic: Option<u32>) -> Self {
        Self::new(xpub, Attributes::new_bootstrap_era(None, network_magic))
    }
    pub fn to_base58(&self) -> String {
        format!("{}", self)
    }
    pub fn from_base58(s: &str) -> Result<Self, String> {
        let bytes = bs58::decode(s).into_vec().map_err(|_| String::from("base58 error"))?;
        Self::from_bytes(bytes)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut addr_bytes = Serializer::new_vec();
        self.serialize(&mut addr_bytes).unwrap();
        addr_bytes.finalize()
    }
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let mut raw = Deserializer::from(std::io::Cursor::new(bytes));
        let addr = ByronAddress::deserialize(&mut raw).map_err(|e| format!("{}", e))?;
        Ok(addr)
    }
    pub fn network_id(&self) -> u8 {
        // premise: during the Byron-era, we had one mainnet (764824073) and many many testnets
        // with each testnet getting a different protocol magic
        // in Shelley, this changes so that:
        // 1) all testnets use the same u8 protocol magic
        // 2) mainnet is re-mapped to a single u8 protocol magic
        // recall: in Byron mainnet, the network_id is omitted from the address to save a few bytes
        let mainnet_network_id = 764824073;
        // so here we return the mainnet id if none is found in the address
        match self.attributes.network_magic {
            // although mainnet should never be explicitly added, we check for it just in case
            Some(x) => if x == mainnet_network_id { 0b0001 } else { 0b000 },
            None => 0b0001, // mainnet is implied if omitted
        }
    }
    /// returns the byron protocol magic embedded in the address, or mainnet id if none is present
    /// note: for bech32 addresses, you need to use network_id instead
    pub fn byron_protocol_magic(&self) -> u32 {
        let mainnet_network_id = 764824073;
        match self.attributes.network_magic {
            Some(x) => x,
            None => mainnet_network_id, // mainnet is implied if omitted
        }
    }
    pub fn attributes(&self) -> Vec<u8> {
        let mut attributes_bytes = Serializer::new_vec();
        self.attributes.serialize(&mut attributes_bytes).unwrap();
        attributes_bytes.finalize()
    }
    // icarus-style address (Ae2)
    pub fn from_icarus_key(key: &Bip32PublicKey, network: u8) -> ByronAddress {
        let mut out = [0u8; 64];
        out.clone_from_slice(&key.as_bytes());

        // need to ensure we use None for mainnet since Byron-era addresses omitted the network id
        let mapped_network_id = if network == 0b0001 { None } else { Some(0b000 as u32) };
        ByronAddress::new_simple(&XPub::from_bytes(out), mapped_network_id)
    }
    pub fn to_address(&self) -> Address {
        Address(AddrType::Byron(self.clone()))
    }
}

impl cbor_event::se::Serialize for ByronAddress {
    fn serialize<'se, W: Write + Sized>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        let addr_bytes = cbor_event::Value::Bytes(self.addr.to_vec());
        cbor::encode_with_crc32_(&(&addr_bytes, &self.attributes, &PubKeyTag()), serializer)?;
        Ok(serializer)
    }
}

impl cbor_event::de::Deserialize for ByronAddress {
    fn deserialize<R: BufRead>(reader: &mut Deserializer<R>) -> cbor_event::Result<Self> {
        let bytes = cbor::raw_with_crc32(reader)?;
        let mut raw = Deserializer::from(std::io::Cursor::new(bytes));
        raw.tuple(3, "ExtendedAddr")?;
        let addr_bytes = raw.bytes()?;
        let addr = addr_bytes.as_slice().try_into().map_err(|_| {
            cbor_event::Error::WrongLen(
                addr_bytes.len() as u64,
                cbor_event::Len::Len(EXTENDED_ADDR_LEN as u64),
                "invalid extended address length",
            )
        })?;
        let attributes = cbor_event::de::Deserialize::deserialize(&mut raw)?;
        let _addr_type: PubKeyTag = cbor_event::de::Deserialize::deserialize(&mut raw)?;

        Ok(ByronAddress { addr, attributes })
    }
}

impl fmt::Display for ByronAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let object_bytes = cbor!(self).unwrap();
        let encoded = bs58::encode(object_bytes.as_slice()).into_string();
        write!(f, "{}", encoded)
    }
}

// calculate the hash of the data using SHA3 digest then using Blake2b224
fn sha3_then_blake2b224(data: &[u8]) -> [u8; 28] {
    let mut sh3 = sha3::Sha3_256::new();
    let mut sh3_out = [0; 32];
    sh3.input(data.as_ref());
    sh3.result(&mut sh3_out);

    let mut b2b = Blake2b::new(28);
    let mut out = [0; 28];
    b2b.input(&sh3_out[..]);
    b2b.result(&mut out);
    out
}

fn hash_spending_data(xpub: &XPub, attrs: &Attributes) -> [u8; 28] {
    let buf = cbor!(&(&PubKeyTag(), &SpendingData(xpub), attrs))
        .expect("serialize the HashedSpendingData's digest data");
    sha3_then_blake2b224(&buf)
}

pub mod cbor {
    use cbor_event::{cbor, Len};
    use cbor_event::se::Serializer;
    use cbor_event::de::Deserializer;
    use crc::crc32;

    pub fn encode_with_crc32_<T, W>(t: &T, s: &mut Serializer<W>) -> cbor_event::Result<()>
        where T: cbor_event::Serialize, W: ::std::io::Write + Sized
    {
        let bytes = cbor!(t)?;
        let crc32 = crc32::checksum_ieee(bytes.as_slice());
        s.write_array(Len::Len(2))?
            .write_tag(24)?
            .write_bytes(&bytes)?
            .write_unsigned_integer(crc32 as u64)?;
        Ok(())
    }

    pub fn raw_with_crc32<R: std::io::BufRead>(raw: &mut Deserializer<R>) -> cbor_event::Result<Vec<u8>> {
        let len = raw.array()?;
        assert!(len == Len::Len(2));

        let tag = raw.tag()?;
        if tag != 24 {
            return Err(cbor_event::Error::CustomError(format!(
                "Invalid Tag: {} but expected 24",
                tag
            )));
        }
        let bytes = raw.bytes()?;
        let crc = raw.unsigned_integer()?;
        let found_crc = crc32::checksum_ieee(bytes.as_slice());
        if crc != found_crc as u64 {
            return Err(cbor_event::Error::CustomError(format!(
                "Invalid CRC32: 0x{:x} but expected 0x{:x}",
                crc, found_crc
            )));
        }
        Ok(bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn crc32() {
            let s = b"The quick brown fox jumps over the lazy dog";
            assert_eq!(0x414fa339, crc32::checksum_ieee(s));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byron_address_parsing() {
        // mainnet address w/ protocol magic omitted
        let addr = ByronAddress::from_base58("Ae2tdPwUPEZ4YjgvykNpoFeYUxoyhNj2kg8KfKWN2FizsSpLUPv68MpTVDo").unwrap();
        assert_eq!(addr.byron_protocol_magic(), 764824073);
        let addr_bytes = addr.to_bytes();
        let addr = ByronAddress::from_bytes(addr_bytes).unwrap();
        assert_eq!(addr.to_base58(), "Ae2tdPwUPEZ4YjgvykNpoFeYUxoyhNj2kg8KfKWN2FizsSpLUPv68MpTVDo");

        // original Byron testnet address
        let addr = ByronAddress::from_base58("2cWKMJemoBakg8XXW1XNFNZ8VFHVrBPfcoEc9amhL3BBMxJXdMiHmSyk3zRp2SDXHJcZr").unwrap();
        assert_eq!(addr.byron_protocol_magic(), 1097911063);
        let addr_bytes = addr.to_bytes();
        let addr = ByronAddress::from_bytes(addr_bytes).unwrap();
        assert_eq!(addr.to_base58(), "2cWKMJemoBakg8XXW1XNFNZ8VFHVrBPfcoEc9amhL3BBMxJXdMiHmSyk3zRp2SDXHJcZr");
    }
}