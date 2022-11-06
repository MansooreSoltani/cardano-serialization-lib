pub mod types;
pub mod chain_crypto;
pub mod crypto;
pub mod address;
pub mod transaction;
pub mod serialization;

use pyo3::prelude::*;
use bip39::{Mnemonic, Language};
use types::*;
use crate::crypto::{Bip32PrivateKey, Vkeywitnesses, TransactionHash, Vkeywitness, Vkey, Bip32PublicKey};
use crate::address::{StakeCredential, EnterpriseAddress, Address};
use crate::transaction::{LinearFee, TransactionBuilder, TransactionOutput, Transaction, TransactionWitnessSet, TransactionInput, TransactionBody};
use cbor_event::se::Serializer;
use cbor_event::Serialize;
use std::io::Read;
use cbor_event::de::*;
use crate::serialization::{DeserializeEmbeddedGroup, Deserialize};

fn harden(index: u32) -> u32 {
    index | 0x80_00_00_00
}

#[pyclass]
struct Utxo {
    transaction_hash: Vec<u8>,
    transaction_index: u32,
    value: u64,
    address: String,
    private_key: String,
}

impl Utxo {
    fn from_tuple(t: &(Vec<u8>, u32, u64, String, String)) -> Self {
        Self {
            transaction_hash: t.0.clone(),
            transaction_index: t.1,
            value: t.2,
            address: t.3.clone(),
            private_key: t.4.clone(),
        }
    }
}

#[pymodule]
fn cardano_serialization_lib(_py: Python, m: &PyModule) -> PyResult<()> {

    #[pyfn(m, "generate_enterprise_address")]
    pub fn generate_enterprise_address_py(
        _py: Python, phrase: String, password: String, network: u8, account: u32, chains: u32, index: u32
    ) -> PyResult<String> {
        let out = generate_enterprise_address(phrase, password, network, account, chains, index);
        Ok(out)
    }

    #[pyfn(m, "generate_child_key_pair")]
    pub fn generate_child_key_pair_py(
        _py: Python, phrase: String, password: String, account: u32
    ) -> PyResult<(String,String)> {
        let out = generate_child_key_pair(phrase, password, account);
        Ok(out)
    }

    #[pyfn(m, "generate_key_pair")]
    pub fn generate_key_pair_py(
        _py: Python, phrase: String, password: String, account: u32
    ) -> PyResult<(String,String)> {
        let out = generate_key_pair(phrase, password, account);
        Ok(out)
    }

    #[pyfn(m, "generate_address_from_master")]
    pub fn generate_address_from_master_py(
        _py: Python, master_key: String, chains: u32, index: u32, network: u8
    ) -> PyResult<String> {
        let out = generate_address_from_master(master_key, chains, index, network);
        Ok(out)
    }

    #[pyfn(m, "generate_address_from_master_public_key")]
    pub fn generate_address_from_master_public_key_py(
        _py: Python, master_key: String, chains: u32, index: u32, network: u8
    ) -> PyResult<String> {
        let out = generate_address_from_master_public_key(master_key, chains, index, network);
        Ok(out)
    }

    #[pyfn(m, "generate_address_from_key")]
    pub fn generate_address_from_key_py(
        _py: Python, master_key: String, network: u8
    ) -> PyResult<String> {
        let out = generate_address_from_key(master_key, network);
        Ok(out)
    }

    #[pyfn(m, "sign_tx")]
    pub fn sign_tx_py(
        _py: Python, tx_hex: String, key: String
    ) -> PyResult<String> {
        let out = sign_tx(tx_hex, key);
        Ok(out)
    }

    #[pyfn(m, "verify_tx")]
    pub fn verify_tx_py(
        _py: Python, tx_hex: String, outputs: Vec<(String, u64)>,
    ) -> PyResult<bool> {
        let out = verify_tx(tx_hex, outputs);
        Ok(out)
    }

    #[pyfn(m, "generate_signed_transaction")]
    pub fn generate_signed_transaction_py(
        _py: Python,
        utxo_list: Vec<(Vec<u8>, u32, u64, String, String)>,
        bech32_to_address: String,
        ttl: u32,
    ) -> PyResult<String> {
        let out = generate_signed_transaction(
            utxo_list.iter().map(|x| Utxo::from_tuple(x)).collect(),
            bech32_to_address,
            ttl,
        );
        Ok(out)
    }

    #[pyfn(m, "create_raw_transaction")]
    pub fn create_raw_transaction_py(
        _py: Python,
        utxo_list: Vec<(Vec<u8>, u32, u64, String, String)>,
        outputs: Vec<(String, u64)>,
        ttl: u32,
        bech32_change_address: String,
    ) -> PyResult<String> {
        let out = create_raw_transaction(
            utxo_list.iter().map(|x| Utxo::from_tuple(x)).collect(),
            outputs,
            ttl,
            bech32_change_address,
        );
        Ok(out)
    }

    Ok(())
}

fn generate_address_from_master(hex_master_key: String, chains: u32, index: u32, network: u8) -> String {
    let bip32_master_key = Bip32PrivateKey::from_bytes(&hex::decode(&hex_master_key).unwrap()).unwrap();
    let child_key = bip32_master_key
        .derive(chains)
        .derive(index);
    let spend = child_key.to_public();
    let spend_raw_key = spend.to_raw();
    let spend_cred = StakeCredential::from_keyhash(&spend_raw_key.hash());
    let address = EnterpriseAddress::new(network, &spend_cred).to_address();
    address.to_bech32(None)
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

fn generate_enterprise_address(phrase: String, password: String, network: u8, account: u32, chains: u32, index: u32) -> String {
    let private_key = _generate_bip32_private_key(phrase, password, account, chains, index);
    let spend = private_key.to_public();
    let spend_raw_key = spend.to_raw();
    let spend_cred = StakeCredential::from_keyhash(&spend_raw_key.hash());
    let address = EnterpriseAddress::new(network, &spend_cred).to_address();
    address.to_bech32(None)
}

fn generate_key_pair(phrase: String, password: String, account: u32) -> (String,String) {
    let mnemonic = Mnemonic::from_phrase(phrase.as_str(), Language::English).unwrap();
    let entropy = mnemonic.entropy();
    let root_key = Bip32PrivateKey::from_bip39_entropy(&entropy, password.as_bytes());
    let master_private_key = root_key
        .derive(harden(1852))
        .derive(harden(1815))
        .derive(harden(account));
    let master_public_key = master_private_key.to_public();
    (hex::encode(master_private_key.as_bytes()), hex::encode(master_public_key.as_bytes()))
}

fn generate_child_key_pair(phrase: String, password: String, index: u32) -> (String,String) {
    let mnemonic = Mnemonic::from_phrase(phrase.as_str(), Language::English).unwrap();
    let entropy = mnemonic.entropy();
    let root_key = Bip32PrivateKey::from_bip39_entropy(&entropy, password.as_bytes());
    let private_key = root_key
        .derive(harden(1852))
        .derive(harden(1815))
        .derive(harden(0))
        .derive(0)
        .derive(index);
    let public_key = private_key.to_public();
    (hex::encode(private_key.as_bytes()), hex::encode(public_key.as_bytes()))
}

fn generate_address_from_key(hex_pub_key: String, network: u8)-> String {
    let bip32_master_key = Bip32PublicKey::from_bytes(&hex::decode(&hex_pub_key).unwrap()).unwrap();
    let spend_raw_key = bip32_master_key.to_raw();
    let spend_cred = StakeCredential::from_keyhash(&spend_raw_key.hash());
    let address = EnterpriseAddress::new(network, &spend_cred).to_address();
    address.to_bech32(None)
}

fn generate_address_from_master_public_key(hex_pub_key: String, chains: u32, index: u32, network: u8)-> String {
    let bip32_master_key = Bip32PublicKey::from_bytes(&hex::decode(&hex_pub_key).unwrap()).unwrap();
    let child_key = bip32_master_key
        .derive(chains)
        .derive(index);
    let spend_raw_key = child_key.to_raw();
    let spend_cred = StakeCredential::from_keyhash(&spend_raw_key.hash());
    let address = EnterpriseAddress::new(network, &spend_cred).to_address();
    address.to_bech32(None)
}

fn generate_signed_transaction(
    utxo_list: Vec<Utxo>,
    bech32_to_address: String,
    ttl: u32,
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
    let linear_fee_ = LinearFee::new(&coefficient, &constant);

    let to_address = Address::from_bech32(bech32_to_address.as_str())
        .expect("Address string for destination is in illegal bech32 string.");
    // build transaction
    let mut tx_builder_ = TransactionBuilder::new(
        &linear_fee_,
        &minimum_utxo_val,
        pool_deposit,
        key_deposit,
    );
    let mut total_amount_ = 0;
    for utxo in utxo_list.as_slice() {
        total_amount_ += &utxo.value;
        let transaction_hash = TransactionHash::from_bytes(utxo.transaction_hash.clone())
            .expect("illegal transaction hash data in utxo");
        let private_key = Bip32PrivateKey::from_bytes(&hex::decode(utxo.private_key.clone()).unwrap()).unwrap();
        let public_key = private_key.to_public().to_raw();
        tx_builder_.add_key_input(
            &public_key.hash(),
            &TransactionInput::new(&transaction_hash, utxo.transaction_index),
            &utxo.value,
        );
    }
    tx_builder_.add_output(&TransactionOutput::new(
        &to_address,
        &(total_amount_)
    )).unwrap();
    tx_builder_.set_ttl(ttl);
    tx_builder_.set_fee(&tx_builder_.min_fee().unwrap());
    let tx_body_ = tx_builder_.build().unwrap_or_else(|e| panic!(e));
    let mut witness_set_ = TransactionWitnessSet::new();
    let mut vkey_witnesses_ = Vkeywitnesses::new();
    let transaction_hash = tx_body_.hash();
    for utxo in utxo_list.as_slice() {
        let private_key = Bip32PrivateKey::from_bytes(&hex::decode(utxo.private_key.clone()).unwrap()).unwrap().to_raw();
        let signature = private_key.sign(transaction_hash.0.as_ref());
        let vkey_witness = Vkeywitness::new(&Vkey::new(&private_key.to_public()), &signature);
        vkey_witnesses_.add(&vkey_witness);
    }
    witness_set_.set_vkeys(&vkey_witnesses_);

    let signed_transaction_ = Transaction::new(
        &tx_body_,
        &witness_set_,
        None,
    );
    let final_fee =linear_fee_.min_fee(&signed_transaction_);

    let linear_fee = LinearFee::new(&coefficient, &constant);
    let mut tx_builder = TransactionBuilder::new(
        &linear_fee,
        &minimum_utxo_val,
        pool_deposit,
        key_deposit,
    );
    let mut total_amount = 0;
    for utxo in utxo_list.as_slice() {
        total_amount += &utxo.value;
        let transaction_hash = TransactionHash::from_bytes(utxo.transaction_hash.clone())
            .expect("illegal transaction hash data in utxo");
        let private_key = Bip32PrivateKey::from_bytes(&hex::decode(utxo.private_key.clone()).unwrap()).unwrap();
        let public_key = private_key.to_public().to_raw();
        tx_builder.add_key_input(
            &public_key.hash(),
            &TransactionInput::new(&transaction_hash, utxo.transaction_index),
            &utxo.value,
        );
    }
    let fee = final_fee.unwrap();
    tx_builder.add_output(&TransactionOutput::new(
        &to_address,
        &(total_amount - fee)
    )).unwrap();
    tx_builder.set_ttl(ttl);
    tx_builder.set_fee(&fee);
    let tx_body = tx_builder.build().unwrap_or_else(|e| panic!(e));
    let mut witness_set = TransactionWitnessSet::new();
    let mut vkey_witnesses = Vkeywitnesses::new();
    let transaction_hash = tx_body.hash();
    for utxo in utxo_list.as_slice() {
        let private_key = Bip32PrivateKey::from_bytes(&hex::decode(utxo.private_key.clone()).unwrap()).unwrap().to_raw();
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

fn create_raw_transaction(
    utxo_list: Vec<Utxo>,
    outputs: Vec<(String, u64)>,
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
        // let private_key = Bip32PrivateKey::from_bytes(&hex::decode(utxo.private_key.clone()).unwrap()).unwrap();
        let bip32_public_key = Bip32PublicKey::from_bytes(&hex::decode(utxo.private_key.clone()).unwrap()).unwrap();
        let public_key = bip32_public_key.to_raw();
        tx_builder.add_key_input(
            &public_key.hash(),
            &TransactionInput::new(&transaction_hash, utxo.transaction_index),
            &utxo.value,
        );
    }
    for output in outputs.as_slice(){
        let to_address = Address::from_bech32(output.0.as_str())
            .expect("Address string for destination is in illegal bech32 string.");
        tx_builder.add_output(&TransactionOutput::new(
            &to_address,
            &output.1
        )).unwrap();
    }

    tx_builder.set_ttl(ttl);
    let _change_is_added = tx_builder.add_change_if_needed(
        &change_address
    ).expect("error while auto creating tx output for change...");
    let tx_body = tx_builder.build().unwrap_or_else(|e| panic!(e));
    hex::encode(tx_body.to_bytes())
}

fn sign_tx(tx_body_hex: String, private_key_hex: String) -> String{
    let private_key = Bip32PrivateKey::from_bytes(&hex::decode(&private_key_hex).unwrap()).unwrap().to_raw();
    let tx_body = TransactionBody::deserialize(&mut Deserializer::from(std::io::Cursor::new(&hex::decode(&tx_body_hex).unwrap()))).unwrap();
    // set up witness set
    let mut witness_set = TransactionWitnessSet::new();
    let mut vkey_witnesses = Vkeywitnesses::new();
    let transaction_hash = tx_body.hash();
    let signature = private_key.sign(transaction_hash.0.as_ref());
    let vkey_witness = Vkeywitness::new(&Vkey::new(&private_key.to_public()), &signature);
    vkey_witnesses.add(&vkey_witness);
    witness_set.set_vkeys(&vkey_witnesses);

    let signed_transaction = Transaction::new(
        &tx_body,
        &witness_set,
        None,
    );
    hex::encode(signed_transaction.to_bytes())
}
fn verify_tx(tx_body_hex: String, outputs: Vec<(String, u64)>) -> bool{
    let tx_body = TransactionBody::deserialize(&mut Deserializer::from(std::io::Cursor::new(&hex::decode(&tx_body_hex).unwrap()))).unwrap();
    let tx_outputs = tx_body.outputs;
    for (i, x) in outputs.clone().iter().enumerate() {
        if tx_outputs.get(i).amount != x.1{
            return  false
        }
        if tx_outputs.get(i).address.to_bech32(None) != x.0{
            return  false;
        }
    }
    if tx_outputs.len() != outputs.len() && tx_outputs.len() != outputs.len() + 1{
        return false
    }
    true
}
