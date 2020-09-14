pub mod types;
pub mod chain_crypto;
pub mod crypto;
pub mod address;
pub mod transaction;
pub mod serialization;

use pyo3::prelude::*;
use bip39::{Mnemonic, Language};
use types::*;
use crate::crypto::Bip32PrivateKey;
use crate::address::{StakeCredential, EnterpriseAddress};


fn harden(index: u32) -> u32 {
    index | 0x80_00_00_00
}

#[pymodule]
fn cardano_serialization_lib(_py: Python, m: &PyModule) -> PyResult<()> {
    #[pyfn(m, "generate_bip32_enterprise_address")]
    pub fn generate_bip32_enterprise_address_py(
        _py: Python, phrase: String, password: String, network: u8, account: u32, chains: u32, index: u32
    ) -> PyResult<String> {
        let out = generate_bip32_enterprise_address(phrase, password, network, account, chains, index);
        Ok(out)
    }
    Ok(())
}

fn generate_bip32_enterprise_address(phrase: String, password: String, network: u8, account: u32, chains: u32, index: u32) -> String {
    let mnemonic = Mnemonic::from_phrase(phrase.as_str(), Language::English).unwrap();
    let entropy = mnemonic.entropy();
    let root_key = Bip32PrivateKey::from_bip39_entropy(&entropy, password.as_bytes());
    let spend = root_key
        .derive(harden(1852))
        .derive(harden(1815))
        .derive(harden(account))
        .derive(chains)
        .derive(index)
        .to_public();
    let spend_raw_key = spend.to_raw();
    let spend_cred = StakeCredential::from_keyhash(&spend_raw_key.hash());
    let address = EnterpriseAddress::new(network, &spend_cred).to_address();
    address.to_bech32(None)
}
