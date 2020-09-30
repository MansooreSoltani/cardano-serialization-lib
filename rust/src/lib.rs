pub mod types;
pub mod chain_crypto;
pub mod crypto;
pub mod address;
pub mod transaction;
pub mod serialization;

use pyo3::prelude::*;
use bip39::{Mnemonic, Language};
use types::*;
use crate::crypto::{Bip32PrivateKey, Vkeywitnesses, TransactionHash, Vkeywitness, Vkey};
use crate::address::{StakeCredential, EnterpriseAddress, Address};
use crate::transaction::{LinearFee, TransactionBuilder, TransactionOutput, Transaction, TransactionWitnessSet, TransactionInput};


fn harden(index: u32) -> u32 {
    index | 0x80_00_00_00
}

#[pyclass]
struct Utxo {
    transaction_hash: Vec<u8>,
    transaction_index: u32,
    value: u64,
    address: String,
    bip32_phrase: String,
    bip32_password: String,
    bip32_account: u32,
    bip32_chains: u32,
    bip32_index: u32
}

impl Utxo {
    fn from_tuple(t: &(Vec<u8>, u32, u64, String, String, String, u32, u32, u32)) -> Self {
        Self {
            transaction_hash: t.0.clone(),
            transaction_index: t.1,
            value: t.2,
            address: t.3.clone(),
            bip32_phrase: t.4.clone(),
            bip32_password: t.5.clone(),
            bip32_account: t.6,
            bip32_chains: t.7,
            bip32_index: t.8,
        }
    }
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

    #[pyfn(m, "generate_transaction_from_bip32_enterprise_address")]
    pub fn generate_transaction_from_bip32_enterprise_address_py(
        _py: Python,
        network: u8,
        utxo_list: Vec<(Vec<u8>, u32, u64, String, String, String, u32, u32, u32)>,
        bech32_to_address: String,
        send_amount: u64,
        ttl: u32,
        bech32_change_address: String,
    ) -> PyResult<String> {
        let out = generate_transaction_from_bip32_enterprise_address(
            network,
            utxo_list.iter().map(|x| Utxo::from_tuple(x)).collect(),
            bech32_to_address,
            send_amount,
            ttl,
            bech32_change_address,
        );
        Ok(out)
    }

    Ok(())
}

fn _generate_bip32_private_key(phrase: String, password: String, account: u32, chains: u32, index: u32) -> Bip32PrivateKey {
    let mnemonic = Mnemonic::from_phrase(phrase.as_str(), Language::English).unwrap();
    let entropy = mnemonic.entropy();
    let root_key = Bip32PrivateKey::from_bip39_entropy(&entropy, password.as_bytes());
    root_key
        .derive(harden(1852))
        .derive(harden(1815))
        .derive(harden(account))
        .derive(chains)
        .derive(index)
}

fn generate_bip32_enterprise_address(phrase: String, password: String, network: u8, account: u32, chains: u32, index: u32) -> String {
    let private_key = _generate_bip32_private_key(phrase, password, account, chains, index);
    let spend = private_key.to_public();
    let spend_raw_key = spend.to_raw();
    let spend_cred = StakeCredential::from_keyhash(&spend_raw_key.hash());
    let address = EnterpriseAddress::new(network, &spend_cred).to_address();
    address.to_bech32(None)
}

fn generate_transaction_from_bip32_enterprise_address(
    network: u8,
    utxo_list: Vec<Utxo>,
    bech32_to_address: String,
    send_amount: u64,
    ttl: u32,
    bech32_change_address: String,
) -> String {
    // follow the protocol parameters
    // those numbers can be found by running `cardano-cli shelley query protocol-parameters`
    // e.g. for testnet you can use the following command
    // cardano-cli shelley query protocol-parameters --testnet-magic 1097911063 --out-file protocol.json
    let minimum_utxo_val: Coin = 1000000;
    let pool_deposit = 500000000;
    let key_deposit = 2000000;
    let coefficient: Coin = 44;
    let constant: Coin = 155381;
    let linear_fee = LinearFee::new(&coefficient, &constant);

    let to_address = Address::from_bech32(bech32_to_address.as_str())
        .expect("Address string for destination is in illegal bech32 string.");
    let change_address = Address::from_bech32(bech32_change_address.as_str())
        .expect("Address string for change is in illegal bech32 string.");

    // build transaction
    let mut tx_builder = TransactionBuilder::new(
        &linear_fee,
        &minimum_utxo_val,
        pool_deposit,
        key_deposit,
    );
    for utxo in utxo_list.as_slice() {
        let transaction_hash = TransactionHash::from_bytes(utxo.transaction_hash.clone())
            .expect("illegal transaction hash data in utxo");
        let utxo_address = generate_bip32_enterprise_address(
            utxo.bip32_phrase.clone(),
            utxo.bip32_password.clone(),
            network,
            utxo.bip32_account,
            utxo.bip32_chains,
            utxo.bip32_index,
        );
        if utxo_address != utxo.address {
            panic!("computed address dose not match with inputted address where computed: {}, inputted: {}", utxo_address, utxo.address)
        }
        let private_key = _generate_bip32_private_key(
            utxo.bip32_phrase.clone(),
            utxo.bip32_password.clone(),
            utxo.bip32_account,
            utxo.bip32_chains,
            utxo.bip32_index,
        );
        let public_key = private_key.to_public().to_raw();
        tx_builder.add_key_input(
            &public_key.hash(),
            &TransactionInput::new(&transaction_hash, utxo.transaction_index),
            &utxo.value,
        );
    }
    tx_builder.add_output(&TransactionOutput::new(
        &to_address,
        &send_amount
    )).unwrap();
    tx_builder.set_ttl(ttl);
    let _change_is_added = tx_builder.add_change_if_needed(
        &change_address
    ).expect("error while auto creating tx output for change...");
    let tx_body = tx_builder.build().unwrap_or_else(|e| panic!(e));

    // set up witness set
    let mut witness_set = TransactionWitnessSet::new();
    let mut vkey_witnesses = Vkeywitnesses::new();
    let transaction_hash = tx_body.hash();
    for utxo in utxo_list.as_slice() {
        let private_key = _generate_bip32_private_key(
            utxo.bip32_phrase.clone(),
            utxo.bip32_password.clone(),
            utxo.bip32_account,
            utxo.bip32_chains,
            utxo.bip32_index,
        ).to_raw();
        let signature = private_key.sign(transaction_hash.0.as_ref());
        let vkey_witness = Vkeywitness::new(&Vkey::new(&private_key.to_public()), &signature);
        vkey_witnesses.add(&vkey_witness);
    }
    witness_set.set_vkeys(&vkey_witnesses);

    let signed_transaction = Transaction::new(
        &tx_body,
        &witness_set,
        None,
    );
    hex::encode(signed_transaction.to_bytes())
}
