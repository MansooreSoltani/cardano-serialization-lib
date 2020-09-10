pub mod base_address;
pub mod pointer_address;
pub mod enterprise_address;
pub mod reward_address;
pub mod byron_address;
pub mod stake_credential;
pub mod pointer;

pub use base_address::*;
pub use pointer_address::*;
pub use enterprise_address::*;
pub use reward_address::*;
pub use byron_address::*;
pub use stake_credential::*;
pub use pointer::*;
use bech32::ToBase32;
use std::io::{Write, BufRead};
use cbor_event::se::Serializer;
use crate::serialization::{Deserialize, DeserializeError, DeserializeFailure};
use cbor_event::de::Deserializer;
use crate::crypto::{Ed25519KeyHash, ScriptHash};

#[derive(Debug, Clone)]
enum AddrType {
    Base(BaseAddress),
    Ptr(PointerAddress),
    Enterprise(EnterpriseAddress),
    Reward(RewardAddress),
    Byron(ByronAddress),
}

#[derive(Debug, Clone)]
pub struct Address(AddrType);

impl Address {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.0 {
            AddrType::Base(base) => {
                let header: u8 = (base.payment.kind() << 4)
                    | (base.stake.kind() << 5)
                    | (base.network & 0xF);
                buf.push(header);
                buf.extend(base.payment.to_raw_bytes());
                buf.extend(base.stake.to_raw_bytes());
            },
            AddrType::Ptr(ptr) => {
                let header: u8 = 0b0100_0000
                    | (ptr.payment.kind() << 4)
                    | (ptr.network & 0xF);
                buf.push(header);
                buf.extend(ptr.payment.to_raw_bytes());
                buf.extend(variable_nat_encode(ptr.stake.slot.into()));
                buf.extend(variable_nat_encode(ptr.stake.tx_index.into()));
                buf.extend(variable_nat_encode(ptr.stake.cert_index.into()));
            },
            AddrType::Enterprise(enterprise) => {
                let header: u8 = 0b0110_0000
                    | (enterprise.payment.kind() << 4)
                    | (enterprise.network & 0xF);
                buf.push(header);
                buf.extend(enterprise.payment.to_raw_bytes());
            },
            AddrType::Reward(reward) => {
                let header: u8 = 0b1110_0000
                    | (reward.payment.kind() << 4)
                    | (reward.network & 0xF);
                buf.push(header);
                buf.extend(reward.payment.to_raw_bytes());
            },
            AddrType::Byron(byron) => {
                buf.extend(byron.to_bytes())
            },
        }
        buf
    }
    fn from_bytes_impl(data: &[u8]) -> Result<Address, DeserializeError> {
        use std::convert::TryInto;
        println!("reading from: {:?}", data);
        // header has 4 bits addr type discrim then 4 bits network discrim.
        // Copied from shelley.cddl:
        //
        // shelley payment addresses:
        // bit 7: 0
        // bit 6: base/other
        // bit 5: pointer/enterprise [for base: stake cred is keyhash/scripthash]
        // bit 4: payment cred is keyhash/scripthash
        // bits 3-0: network id
        //
        // reward addresses:
        // bits 7-5: 111
        // bit 4: credential is keyhash/scripthash
        // bits 3-0: network id
        //
        // byron addresses:
        // bits 7-4: 1000
        (|| -> Result<Self, DeserializeError> {
            let header = data[0];
            let network = header & 0x0F;
            const HASH_LEN: usize = Ed25519KeyHash::BYTE_COUNT;
            // should be static assert but it's maybe not worth importing a whole external crate for it now
            assert_eq!(ScriptHash::BYTE_COUNT, HASH_LEN);
            // checks the /bit/ bit of the header for key vs scripthash then reads the credential starting at byte position /pos/
            let read_addr_cred = |bit: u8, pos: usize| {
                let hash_bytes: [u8; HASH_LEN] = data[pos..pos+HASH_LEN].try_into().unwrap();
                let x = if header & (1 << bit)  == 0 {
                    StakeCredential::from_keyhash(&Ed25519KeyHash::from(hash_bytes))
                } else {
                    StakeCredential::from_scripthash(&ScriptHash::from(hash_bytes))
                };
                println!("read cred: {:?}", x);
                x
            };
            let addr = match (header & 0xF0) >> 4 {
                // base
                0b0000 | 0b0001 | 0b0010 | 0b0011 => {
                    const BASE_ADDR_SIZE: usize = 1 + HASH_LEN * 2;
                    if data.len() < BASE_ADDR_SIZE {
                        return Err(cbor_event::Error::NotEnough(data.len(), BASE_ADDR_SIZE).into());
                    }
                    if data.len() > BASE_ADDR_SIZE {
                        return Err(cbor_event::Error::TrailingData.into());
                    }
                    AddrType::Base(BaseAddress::new(network, &read_addr_cred(4, 1), &read_addr_cred(5, 1 + HASH_LEN)))
                },
                // pointer
                0b0100 | 0b0101 => {
                    // header + keyhash + 3 natural numbers (min 1 byte each)
                    const PTR_ADDR_MIN_SIZE: usize = 1 + HASH_LEN + 1 + 1 + 1;
                    if data.len() < PTR_ADDR_MIN_SIZE {
                        // possibly more, but depends on how many bytes the natural numbers are for the pointer
                        return Err(cbor_event::Error::NotEnough(data.len(), PTR_ADDR_MIN_SIZE).into());
                    }
                    let mut byte_index = 1;
                    let payment_cred = read_addr_cred(4, 1);
                    byte_index += HASH_LEN;
                    let (slot, slot_bytes) = variable_nat_decode(&data[byte_index..])
                        .ok_or(DeserializeError::new("Address.Pointer.slot", DeserializeFailure::VariableLenNatDecodeFailed))?;
                    byte_index += slot_bytes;
                    let (tx_index, tx_bytes) = variable_nat_decode(&data[byte_index..])
                        .ok_or(DeserializeError::new("Address.Pointer.tx_index", DeserializeFailure::VariableLenNatDecodeFailed))?;
                    byte_index += tx_bytes;
                    let (cert_index, cert_bytes) = variable_nat_decode(&data[byte_index..])
                        .ok_or(DeserializeError::new("Address.Pointer.cert_index", DeserializeFailure::VariableLenNatDecodeFailed))?;
                    byte_index += cert_bytes;
                    if byte_index < data.len() {
                        return Err(cbor_event::Error::TrailingData.into());
                    }
                    AddrType::Ptr(
                        PointerAddress::new(
                            network,
                            &payment_cred,
                            &Pointer::new(
                                slot.try_into().map_err(|_| DeserializeError::new("Address.Pointer.slot", DeserializeFailure::CBOR(cbor_event::Error::ExpectedU32)))?,
                                tx_index.try_into().map_err(|_| DeserializeError::new("Address.Pointer.tx_index", DeserializeFailure::CBOR(cbor_event::Error::ExpectedU32)))?,
                                cert_index.try_into().map_err(|_| DeserializeError::new("Address.Pointer.cert_index", DeserializeFailure::CBOR(cbor_event::Error::ExpectedU32)))?)))
                },
                // enterprise
                0b0110 | 0b0111 => {
                    const ENTERPRISE_ADDR_SIZE: usize = 1 + HASH_LEN;
                    if data.len() < ENTERPRISE_ADDR_SIZE {
                        return Err(cbor_event::Error::NotEnough(data.len(), ENTERPRISE_ADDR_SIZE).into());
                    }
                    if data.len() > ENTERPRISE_ADDR_SIZE {
                        return Err(cbor_event::Error::TrailingData.into());
                    }
                    AddrType::Enterprise(EnterpriseAddress::new(network, &read_addr_cred(4, 1)))
                },
                // reward
                0b1110 | 0b1111 => {
                    const REWARD_ADDR_SIZE: usize = 1 + HASH_LEN;
                    if data.len() < REWARD_ADDR_SIZE {
                        return Err(cbor_event::Error::NotEnough(data.len(), REWARD_ADDR_SIZE).into());
                    }
                    if data.len() > REWARD_ADDR_SIZE {
                        return Err(cbor_event::Error::TrailingData.into());
                    }
                    AddrType::Reward(RewardAddress::new(network, &read_addr_cred(4, 1)))
                }
                // byron
                0b1000 => {
                    // note: 0b1000 was chosen because all existing Byron addresses actually start with 0b1000
                    // Therefore you can re-use Byron addresses as-is
                    match ByronAddress::from_bytes(data.to_vec()) {
                        Ok(addr) => AddrType::Byron(addr),
                        Err(e) => return Err(cbor_event::Error::CustomError(e).into()),
                    }
                },
                _ => return Err(DeserializeFailure::BadAddressType(header).into()),
            };
            Ok(Address(addr))
        })().map_err(|e| e.annotate("Address"))
    }
    pub fn to_bech32(&self, prefix: Option<String>) -> String {
        let human_readable_part = match prefix {
            Some(prefix_str) => prefix_str,
            None => {
                // see CIP5 for bech32 prefix rules
                let prefix_header = match &self.0 {
                    AddrType::Reward(_) => "stake",
                    _ => "addr",
                };
                let prefix_tail = match &self.network_id() {
                    0b0001 => "",
                    _ => "_test",
                };
                format!("{}{}", prefix_header, prefix_tail)
            }
        };
        bech32::encode(&human_readable_part, self.to_bytes().to_base32()).unwrap()
    }
    pub fn network_id(&self) -> u8 {
        match &self.0 {
            AddrType::Base(a) => a.network,
            AddrType::Enterprise(a) => a.network,
            AddrType::Ptr(a) => a.network,
            AddrType::Reward(a) => a.network,
            AddrType::Byron(a) => a.network_id(),
        }
    }
}

impl cbor_event::se::Serialize for Address {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_bytes(self.to_bytes())
    }
}

impl Deserialize for Address {
    fn deserialize<R: BufRead>(raw: &mut Deserializer<R>) -> Result<Self, DeserializeError> {
        Self::from_bytes_impl(raw.bytes()?.as_ref())
    }
}

// returns (Number represented, bytes read) if valid encoding
// or None if decoding prematurely finished
fn variable_nat_decode(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut output = 0u64;
    let mut bytes_read = 0;
    for byte in bytes {
        output = (output << 7) | (byte & 0x7F) as u64;
        bytes_read += 1;
        if (byte & 0x80) == 0 {
            return Some((output, bytes_read));
        }
    }
    None
}

fn variable_nat_encode(mut num: u64) -> Vec<u8> {
    let mut output = vec![num as u8 & 0x7F];
    num /= 128;
    while num > 0 {
        output.push((num & 0x7F) as u8 | 0x80);
        num /= 128;
    }
    output.reverse();
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::*;
    use bip39::{Mnemonic, Language};

    fn root_key_12() -> Bip32PrivateKey {
        // let entropy = [0xdf, 0x9e, 0xd2, 0x5e, 0xd1, 0x46, 0xbf, 0x43, 0x33, 0x6a, 0x5d, 0x7c, 0xf7, 0x39, 0x59, 0x94];
        let phrase = "test walk nut penalty hip pave soap entry language right filter choice";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let entropy = mnemonic.entropy();
        Bip32PrivateKey::from_bip39_entropy(&entropy, &[])
    }

    fn root_key_15() -> Bip32PrivateKey {
        let phrase = "art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let entropy = mnemonic.entropy();
        Bip32PrivateKey::from_bip39_entropy(&entropy, &[])
    }

    fn harden(index: u32) -> u32 {
        index | 0x80_00_00_00
    }

    #[test]
    fn bip32_15_base() {
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();
        let spend_raw_key = spend.to_raw();
        let stake_raw_key = stake.to_raw();
        let spend_cred = StakeCredential::from_keyhash(&spend_raw_key.hash());
        let stake_cred = StakeCredential::from_keyhash(&stake_raw_key.hash());
        let testnet_address = BaseAddress::new(0, &spend_cred, &stake_cred).to_address();
        assert_eq!(testnet_address.to_bech32(None), "addr_test1qpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5ewvxwdrt70qlcpeeagscasafhffqsxy36t90ldv06wqrk2qum8x5w");
        let mainnet_address = BaseAddress::new(1, &spend_cred, &stake_cred).to_address();
        assert_eq!(mainnet_address.to_bech32(None), "addr1q9u5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5ewvxwdrt70qlcpeeagscasafhffqsxy36t90ldv06wqrk2qld6xc3");
    }

    #[test]
    fn bip32_15_pointer() {
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let spend_raw_key = spend.to_raw();
        let spend_cred = StakeCredential::from_keyhash(&spend_raw_key.hash());
        let addr_net_0 = PointerAddress::new(0, &spend_cred, &Pointer::new(1, 2, 3)).to_address();
        assert_eq!(addr_net_0.to_bech32(None), "addr_test1gpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5egpqgpsdhdyc0");
        let addr_net_3 = PointerAddress::new(1, &spend_cred, &Pointer::new(24157, 177, 42)).to_address();
        assert_eq!(addr_net_3.to_bech32(None), "addr1g9u5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5evph3wczvf2kd5vam");
    }

    #[test]
    fn bip32_15_enterprise() {
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let spend_raw_key = spend.to_raw();
        let spend_cred = StakeCredential::from_keyhash(&spend_raw_key.hash());
        let testnet_address = EnterpriseAddress::new(0, &spend_cred).to_address();
        assert_eq!(testnet_address.to_bech32(None), "addr_test1vpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5eg57c2qv");
        let mainnet_address = EnterpriseAddress::new(1, &spend_cred).to_address();
        assert_eq!(mainnet_address.to_bech32(None), "addr1v9u5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5eg0kvk0f");
    }

    #[test]
    fn bip32_15_byron() {
        let byron_key = root_key_15()
            .derive(harden(44))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let byron_addr = ByronAddress::from_icarus_key(&byron_key, 0b0001);
        assert_eq!(byron_addr.to_base58(), "Ae2tdPwUPEZHtBmjZBF4YpMkK9tMSPTE2ADEZTPN97saNkhG78TvXdp3GDk");
        assert_eq!(byron_addr.network_id(), 0b0001);
    }

    #[test]
    fn bip32_12_reward() {
        let staking_key = root_key_12()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();
        let stake_raw_key = staking_key.to_raw();
        let staking_cred = StakeCredential::from_keyhash(&stake_raw_key.hash());
        let testnet_address = RewardAddress::new(0, &staking_cred).to_address();
        assert_eq!(testnet_address.to_bech32(None), "stake_test1uqevw2xnsc0pvn9t9r9c7qryfqfeerchgrlm3ea2nefr9hqp8n5xl");
        let mainnet_address = RewardAddress::new(1, &staking_cred).to_address();
        assert_eq!(mainnet_address.to_bech32(None), "stake1uyevw2xnsc0pvn9t9r9c7qryfqfeerchgrlm3ea2nefr9hqxdekzz");
    }
}
