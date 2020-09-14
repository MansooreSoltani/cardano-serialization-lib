use std::collections::BTreeSet;
use crate::crypto::{ScriptHash, Ed25519KeyHash, Bip32PrivateKey, Vkeywitnesses, Vkeywitness, Vkey, BootstrapWitnesses, BootstrapWitness};
use crate::address::{ByronAddress, Address};
use crate::transaction::{TransactionInput, TransactionBody, TransactionInputs, TransactionOutputs, TransactionOutput, Certificates, Withdrawals, TransactionMetadata, LinearFee, TransactionWitnessSet, Transaction, Certificate, CertificateEnum};
use crate::Coin;

#[derive(Clone, Debug)]
pub struct TransactionBuilder {
    minimum_utxo_val: u64,
    pool_deposit: u64,
    key_deposit: u64,
    fee_algo: LinearFee,
    inputs: TransactionBuilderInputs,
    outputs: TransactionOutputs,
    fee: Option<Coin>,
    ttl: Option<u32>, // absolute slot number
    certs: Option<Certificates>,
    withdrawals: Option<Withdrawals>,
    metadata: Option<TransactionMetadata>,
    input_types: MockWitnessSet,
}

impl TransactionBuilder {
    pub fn new(
        linear_fee: &LinearFee,
        // protocol parameter that defines the minimum value a newly created UTXO can contain
        minimum_utxo_val: &Coin,
        pool_deposit: u64, // protocol parameter
        key_deposit: u64, // protocol parameter
    ) -> Self {
        Self {
            minimum_utxo_val: minimum_utxo_val.clone(),
            key_deposit,
            pool_deposit,
            fee_algo: linear_fee.clone(),
            inputs: Vec::new(),
            outputs: TransactionOutputs::new(),
            fee: None,
            ttl: None,
            certs: None,
            withdrawals: None,
            metadata: None,
            input_types: MockWitnessSet {
                vkeys: BTreeSet::new(),
                scripts: BTreeSet::new(),
                bootstraps: BTreeSet::new(),
            },
        }
    }
    // We have to know what kind of inputs these are to know what kind of mock witnesses to create since
    // 1) mock witnesses have different lengths depending on the type which changes the expecting fee
    // 2) Witnesses are a set so we need to get rid of duplicates to avoid over-estimating the fee
    pub fn add_key_input(&mut self, hash: &Ed25519KeyHash, input: &TransactionInput, amount: &Coin) {
        self.inputs.push(TxBuilderInput {
            input: input.clone(),
            amount: amount.clone(),
        });
        self.input_types.vkeys.insert(hash.clone());
    }
    pub fn add_script_input(&mut self, hash: &ScriptHash, input: &TransactionInput, amount: &Coin) {
        self.inputs.push(TxBuilderInput {
            input: input.clone(),
            amount: amount.clone(),
        });
        self.input_types.scripts.insert(hash.clone());
    }
    pub fn add_bootstrap_input(&mut self, hash: &ByronAddress, input: &TransactionInput, amount: &Coin) {
        self.inputs.push(TxBuilderInput {
            input: input.clone(),
            amount: amount.clone(),
        });
        self.input_types.bootstraps.insert(hash.to_bytes());
    }
    pub fn add_output(&mut self, output: &TransactionOutput) -> Result<(), String> {
        if output.amount() < self.minimum_utxo_val {
            Err(format!(
                "Value {} less than the minimum UTXO value {}",
                output.amount(),
                &self.minimum_utxo_val
            ))
        } else {
            self.outputs.add(output);
            Ok(())
        }
    }
    pub fn set_fee(&mut self, fee: &Coin) {
        self.fee = Some(fee.clone())
    }
    pub fn get_fee(&self) -> Option<Coin> {
        self.fee.clone()
    }
    /// calculates how much the fee would increase if you added a given output
    pub fn fee_for_output(&mut self, output: &TransactionOutput) -> Result<Coin, String> {
        let mut self_copy = self.clone();
        // we need some value for these for it to be a a valid transaction
        // but since we're only calculating the different between the fee of two transactions
        // it doesn't matter what these are set as, since it cancels out
        self_copy.set_ttl(0);
        let fee: Coin = 0;
        self_copy.set_fee(&fee);
        let fee_before = min_fee(&self_copy)?;
        self_copy.add_output(&output)?;
        let fee_after = min_fee(&self_copy)?;
        match fee_after.checked_sub(fee_before) {
            Some(value) => Ok(value),
            None => Err(String::from("underflow")),
        }
    }
    pub fn get_input(&self) -> Result<Coin, String> {
        let explicit = self.get_explicit_input()?;
        let implicit = self.get_implicit_input()?;
        match explicit.checked_add(implicit) {
            Some(value) => Ok(value),
            None => Err(String::from("overflow")),
        }
    }
    /// does not include refunds or withdrawals
    pub fn get_explicit_input(&self) -> Result<Coin, String> {
        self.inputs.total()
    }
    /// withdrawals and refunds
    pub fn get_implicit_input(&self) -> Result<Coin, String> {
        let withdrawal_sum = match &self.withdrawals {
            None => 0 as u64,
            Some(x) => x.total()?,
        };
        let certificate_refund: u64 = match &self.certs {
            None => 0 as u64,
            Some(certs) => certs.total_for_input(self.pool_deposit, self.key_deposit)?,
        };
        match withdrawal_sum.checked_add(certificate_refund) {
            Some(value) => Ok(value),
            None => Err(String::from("overflow"))
        }
    }
    pub fn get_output(&self) -> Result<Coin, String> {
        let explicit = self.get_explicit_output()?;
        let deposit = self.get_deposit()?;
        match explicit.checked_add(deposit) {
            Some(value) => Ok(value),
            None => Err(String::from("overflow")),
        }
    }
    /// does not include fee
    pub fn get_explicit_output(&self) -> Result<Coin, String> {
        self.outputs.total()
    }
    pub fn get_deposit(&self) -> Result<Coin, String> {
        match &self.certs {
            None => Ok(0),
            Some(certs) => certs.total_for_output(self.pool_deposit, self.key_deposit)
        }
    }
    /// Warning: this function will mutate the /fee/ field
    pub fn add_change_if_needed(&mut self, address: &Address) -> Result<bool, String> {
        let fee = match &self.fee {
            None => self.min_fee(),
            // generating the change output involves changing the fee
            Some(_x) => return Err(String::from("Cannot calculate change if fee was explicitly specified")),
        }?;
        let input_total = self.get_input()?;
        let output_total = self.get_output()?;
        let output_total_with_fee = match output_total.checked_add(fee) {
            Some(value) => Ok(value),
            None => Err(String::from("overflow")),
        }?;
        match input_total >= output_total_with_fee {
            false => return Err(String::from("Insufficient input in transaction")),
            true => {
                // check how much the fee would increase if we added a change output
                let fee_for_change = self.fee_for_output(&TransactionOutput {
                    address: address.clone(),
                    // maximum possible output to maximize fee from adding this output
                    // this may over-estimate the fee by a few bytes but that's okay
                    amount: 0x1_00_00_00_00,
                })?;
                let new_fee = match fee.checked_add(fee_for_change) {
                    Some(value) => Ok(value),
                    None => Err(String::from("overflow")),
                }?;
                // needs to have at least minimum_utxo_val leftover for the change to be a valid UTXO entry
                let output_total_with_new_fee = match output_total.checked_add(new_fee) {
                    Some(value) => Ok(value),
                    None => Err(String::from("overflow")),
                }?;
                let output_total_with_new_fee = match output_total_with_new_fee.checked_add(self.minimum_utxo_val) {
                    Some(value) => Ok(value),
                    None => Err(String::from("overflow")),
                }?;
                let left_amount = match input_total.checked_sub(output_total) {
                    Some(value) => Ok(value),
                    None => Err(String::from("underflow")),
                }?;
                match input_total >= output_total_with_new_fee {
                    false => {
                        // recall: we originally assumed the fee was the maximum possible so we definitely have enough input to cover whatever fee it ends up being
                        self.set_fee(&left_amount);
                        return Ok(false) // not enough input to covert the extra fee from adding an output so we just burn whatever is left
                    },
                    true => {
                        // recall: we originally assumed the fee was the maximum possible so we definitely have enough input to cover whatever fee it ends up being
                        let change_amount = match left_amount.checked_sub(new_fee) {
                            Some(value) => Ok(value),
                            None => Err(String::from("underflow")),
                        }?;
                        self.set_fee(&new_fee);
                        self.add_output(&TransactionOutput {
                            address: address.clone(),
                            amount: change_amount,
                        })?;
                    },
                };
            },
        };
        Ok(true)
    }
    /// warning: sum of all parts of a transaction must equal 0. You cannot just set the fee to the min value and forget about it
    /// warning: min_fee may be slightly larger than the actual minimum fee (ex: a few lovelaces)
    /// this is done to simplify the library code, but can be fixed later
    pub fn min_fee(&self) -> Result<Coin, String> {
        let mut self_copy = self.clone();
        let fee: Coin = 0x1_00_00_00_00;
        self_copy.set_fee(&fee);
        min_fee(&self_copy)
    }
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = Some(ttl)
    }
    pub fn set_certs(&mut self, certs: &Certificates) {
        self.certs = Some(certs.clone());
        for cert in &certs.0 {
            witness_keys_for_cert(cert, &mut self.input_types.vkeys);
        };
    }
    pub fn build(&self) -> Result<TransactionBody, String> {
        let fee = self.fee.ok_or_else(|| String::from("Fee not specified"))?;
        let ttl = self.ttl.ok_or_else(|| String::from("ttl not specified"))?;
        Ok(TransactionBody {
            inputs: TransactionInputs(self.inputs.iter().map(|ref tx_builder_input| tx_builder_input.input.clone()).collect()),
            outputs: self.outputs.clone(),
            fee: fee,
            ttl: ttl,
            certs: self.certs.clone(),
            withdrawals: self.withdrawals.clone(),
            update: None,
            metadata_hash: match &self.metadata {
                None => None,
                Some(x) => Some(x.to_hash()),
            },
        })
    }
}

#[derive(Clone, Debug)]
struct TxBuilderInput {
    input: TransactionInput,
    amount: Coin, // we need to keep track of the amount in the inputs for input selection
}

type TransactionBuilderInputs = Vec<TxBuilderInput>;

trait TxBuilderInputs {
    fn total(&self) -> Result<Coin, String>;
}

impl TxBuilderInputs for TransactionBuilderInputs {
    fn total(&self) -> Result<Coin, String> {
        self.iter()
            .try_fold(
                0 as u64,
                |sum: u64, item| {
                    match sum.checked_add(item.amount) {
                        Some(value) => Ok(value),
                        None => Err(String::from("overflow")),
                    }
                }
            )
    }
}

#[derive(Clone, Debug)]
struct MockWitnessSet {
    vkeys: BTreeSet<Ed25519KeyHash>,
    scripts: BTreeSet<ScriptHash>,
    bootstraps: BTreeSet<Vec<u8>>,
}

fn min_fee(tx_builder: &TransactionBuilder) -> Result<Coin, String> {
    let body = tx_builder.build()?;
    let fake_key_root = Bip32PrivateKey::from_bip39_entropy(
        // art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy
        &[0x0c, 0xcb, 0x74, 0xf3, 0x6b, 0x7d, 0xa1, 0x64, 0x9a, 0x81, 0x44, 0x67, 0x55, 0x22, 0xd4, 0xd8, 0x09, 0x7c, 0x64, 0x12],
        &[]
    );
    // recall: this includes keys for input, certs and withdrawals
    let vkeys = match tx_builder.input_types.vkeys.len() {
        0 => None,
        x => {
            let mut result = Vkeywitnesses::new();
            let raw_key = fake_key_root.to_raw();
            for _i in 0..x {
                result.add(&Vkeywitness::new(
                    &Vkey::new(&raw_key.to_public()),
                    &raw_key.sign([1u8; 100].as_ref())
                ));
            }
            Some(result)
        },
    };
    let script_keys = match tx_builder.input_types.scripts.len() {
        0 => None,
        _x => {
            // TODO: figure out how to populate fake witnesses for these
            return Err(String::from("Script inputs not supported yet"))
        },
    };
    let bootstrap_keys = match tx_builder.input_types.bootstraps.len() {
        0 => None,
        _x => {
            let mut result = BootstrapWitnesses::new();
            for addr in &tx_builder.input_types.bootstraps {
                // picking icarus over daedalus for fake witness generation shouldn't matter
                let chain_code = fake_key_root.chaincode();
                let raw_key = fake_key_root.to_raw();
                let vkey = Vkey::new(&raw_key.to_public());
                let tx_body_hash_bytes = body.hash().to_bytes();
                let signature = raw_key.sign(&tx_body_hash_bytes);
                let byron_address = &ByronAddress::from_bytes(addr.clone()).unwrap();
                let boot_strap_witness = BootstrapWitness::new(
                    &vkey,
                    &signature,
                    chain_code,
                    byron_address.attributes(),
                );
                result.add(&boot_strap_witness);
            }
            Some(result)
        },
    };
    let witness_set = TransactionWitnessSet {
        vkeys: vkeys,
        scripts: script_keys,
        bootstraps: bootstrap_keys,
    };
    let full_tx = Transaction {
        body,
        witness_set,
        metadata: tx_builder.metadata.clone(),
    };
    tx_builder.fee_algo.min_fee(&full_tx)
}

// comes from witsVKeyNeeded in the Ledger spec
fn witness_keys_for_cert(cert_enum: &Certificate, keys: &mut BTreeSet<Ed25519KeyHash>) {
    match &cert_enum.0 {
        // stake key registrations do not require a witness
        CertificateEnum::StakeRegistration(_cert) => {},
        CertificateEnum::StakeDeregistration(cert) => {
            keys.insert(cert.stake_credential().to_keyhash().unwrap());
        },
        CertificateEnum::StakeDelegation(cert) => {
            keys.insert(cert.stake_credential().to_keyhash().unwrap());
        },
        CertificateEnum::PoolRegistration(cert) => {
            for owner in &cert.pool_params().pool_owners().0 {
                keys.insert(owner.clone());
            }
            keys.insert(
                Ed25519KeyHash::from_bytes(cert.pool_params().operator().to_bytes()).unwrap()
            );
        },
        CertificateEnum::PoolRetirement(cert) => {
            keys.insert(
                Ed25519KeyHash::from_bytes(cert.pool_keyhash().to_bytes()).unwrap()
            );
        },
        CertificateEnum::GenesisKeyDelegation(cert) => {
            keys.insert(
                Ed25519KeyHash::from_bytes(cert.genesis_delegate_hash().to_bytes()).unwrap()
            );
        },
        // not witness as there is no single core node or genesis key that posts the certificate
        CertificateEnum::MoveInstantaneousRewardsCert(_cert) => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Mnemonic, Language};
    use crate::address::{StakeCredential, BaseAddress};
    use crate::crypto::TransactionHash;
    use crate::transaction::{StakeRegistration, StakeDelegation};

    fn genesis_id() -> TransactionHash {
        TransactionHash::from([0u8; TransactionHash::BYTE_COUNT])
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
    fn build_tx_with_change() {
        let coefficient: Coin = 500;
        let constant: Coin = 2;
        let minimum_utxo_val: Coin = 1;
        let pool_deposit = 1;
        let key_deposit = 1;
        let linear_fee = LinearFee::new(&coefficient, &constant);
        let mut tx_builder = TransactionBuilder::new(
            &linear_fee,
            &minimum_utxo_val,
            pool_deposit,
            key_deposit,
        );
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();
        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw().hash());
        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw().hash());
        let spend_address = BaseAddress::new(0, &spend_cred, &stake_cred).to_address();
        let change_address = BaseAddress::new(0, &change_cred, &stake_cred).to_address();
        tx_builder.add_key_input(
            &spend.to_raw().hash(),
            &TransactionInput::new(&genesis_id(), 0),
            &1_000_000
        );
        tx_builder.add_output(&TransactionOutput::new(
            &spend_address,
            &10
        )).unwrap();
        tx_builder.set_ttl(1000);
        let change_is_added = tx_builder.add_change_if_needed(
            &change_address
        );
        assert!(change_is_added.unwrap());
        assert_eq!(tx_builder.outputs.len(), 2);
        let total_input = tx_builder.get_input().unwrap();
        let total_output = tx_builder.get_output().unwrap().checked_add(tx_builder.get_fee().unwrap()).unwrap();
        assert_eq!(total_input, total_output);
        let _ = tx_builder.build(); // just test that it doesn't throw
    }

    #[test]
    fn build_tx_without_change() {
        let coefficient: Coin = 500;
        let constant: Coin = 2;
        let minimum_utxo_val: Coin = 1;
        let pool_deposit = 1;
        let key_deposit = 1;
        let linear_fee = LinearFee::new(&coefficient, &constant);
        let mut tx_builder = TransactionBuilder::new(
            &linear_fee,
            &minimum_utxo_val,
            pool_deposit,
            key_deposit,
        );
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();
        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw().hash());
        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw().hash());
        let spend_address = BaseAddress::new(0, &spend_cred, &stake_cred).to_address();
        let change_address = BaseAddress::new(0, &change_cred, &stake_cred).to_address();
        tx_builder.add_key_input(
            &spend.to_raw().hash(),
            &TransactionInput::new(&genesis_id(), 0),
            &1_000_000
        );
        tx_builder.add_output(&TransactionOutput::new(
            &spend_address,
            &880_000
        )).unwrap();
        tx_builder.set_ttl(1000);
        let change_is_added = tx_builder.add_change_if_needed(
            &change_address
        );
        assert!(!change_is_added.unwrap());
        assert_eq!(tx_builder.outputs.len(), 1);
        let total_input = tx_builder.get_input().unwrap();
        let total_output = tx_builder.get_output().unwrap().checked_add(tx_builder.get_fee().unwrap()).unwrap();
        assert_eq!(total_input, total_output);
        let _ = tx_builder.build(); // just test that it doesn't throw
    }

    #[test]
    fn build_tx_with_certs() {
        let coefficient: Coin = 500;
        let constant: Coin = 2;
        let minimum_utxo_val: Coin = 1;
        let pool_deposit = 1;
        let key_deposit = 1_000_000;
        let linear_fee = LinearFee::new(&coefficient, &constant);
        let mut tx_builder = TransactionBuilder::new(
            &linear_fee,
            &minimum_utxo_val,
            pool_deposit,
            key_deposit,
        );
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw().hash());
        tx_builder.add_key_input(
            &spend.to_raw().hash(),
            &TransactionInput::new(&genesis_id(), 0),
            &5_000_000
        );
        tx_builder.set_ttl(1000);
        let mut certs = Certificates::new();
        certs.add(&Certificate::new_stake_registration(&StakeRegistration::new(&stake_cred)));
        certs.add(&Certificate::new_stake_delegation(&StakeDelegation::new(
            &stake_cred,
            &stake.to_raw().hash(), // in reality, this should be the pool owner's key, not ours
        )));
        tx_builder.set_certs(&certs);
        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw().hash());
        let change_address = BaseAddress::new(0, &change_cred, &stake_cred).to_address();
        tx_builder.add_change_if_needed(
            &change_address
        ).unwrap();
        assert_eq!(tx_builder.min_fee().unwrap(), 213502);
        assert_eq!(tx_builder.get_fee().unwrap(), 215502);
        assert_eq!(tx_builder.get_deposit().unwrap(), 1_000_000);
        assert_eq!(tx_builder.outputs.len(), 1);
        let total_input = tx_builder.get_input().unwrap();
        let total_output = tx_builder.get_output().unwrap().checked_add(tx_builder.get_fee().unwrap()).unwrap();
        assert_eq!(total_input, total_output);
        let _final_tx = tx_builder.build(); // just test that it doesn't throw
    }

    #[test]
    fn build_tx_exact_amount() {
        // transactions where sum(input) == sum(output) exact should pass
        let coefficient: Coin = 0;
        let constant: Coin = 0;
        let minimum_utxo_val: Coin = 1;
        let pool_deposit = 0;
        let key_deposit = 0;
        let linear_fee = LinearFee::new(&coefficient, &constant);
        let mut tx_builder = TransactionBuilder::new(
            &linear_fee,
            &minimum_utxo_val,
            pool_deposit,
            key_deposit,
        );
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();
        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw().hash());
        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw().hash());
        let spend_address = BaseAddress::new(0, &spend_cred, &stake_cred).to_address();
        let change_address = BaseAddress::new(0, &change_cred, &stake_cred).to_address();
        tx_builder.add_key_input(
            &&spend.to_raw().hash(),
            &TransactionInput::new(&genesis_id(), 0),
            &5
        );
        tx_builder.add_output(&TransactionOutput::new(
            &spend_address,
            &5
        )).unwrap();
        tx_builder.set_ttl(0);
        let change_is_added = tx_builder.add_change_if_needed(
            &change_address
        ).unwrap();
        assert_eq!(change_is_added, false);
        let final_tx = tx_builder.build().unwrap();
        assert_eq!(final_tx.outputs().len(), 1);
    }

    #[test]
    fn build_tx_insufficient_deposit() {
        let coefficient: Coin = 0;
        let constant: Coin = 0;
        let minimum_utxo_val: Coin = 1;
        let pool_deposit = 0;
        let key_deposit = 5;
        let linear_fee = LinearFee::new(&coefficient, &constant);
        let mut tx_builder = TransactionBuilder::new(
            &linear_fee,
            &minimum_utxo_val,
            pool_deposit,
            key_deposit,
        );
        let spend = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(0)
            .derive(0)
            .to_public();
        let change_key = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(1)
            .derive(0)
            .to_public();
        let stake = root_key_15()
            .derive(harden(1852))
            .derive(harden(1815))
            .derive(harden(0))
            .derive(2)
            .derive(0)
            .to_public();
        let spend_cred = StakeCredential::from_keyhash(&spend.to_raw().hash());
        let change_cred = StakeCredential::from_keyhash(&change_key.to_raw().hash());
        let stake_cred = StakeCredential::from_keyhash(&stake.to_raw().hash());
        let spend_address = BaseAddress::new(0, &spend_cred, &stake_cred).to_address();
        let change_address = BaseAddress::new(0, &change_cred, &stake_cred).to_address();
        tx_builder.add_key_input(
            &&spend.to_raw().hash(),
            &TransactionInput::new(&genesis_id(), 0),
            &5
        );
        tx_builder.add_output(&TransactionOutput::new(
            &spend_address,
            &5
        )).unwrap();
        tx_builder.set_ttl(0);

        // add a cert which requires a deposit
        let mut certs = Certificates::new();
        certs.add(&Certificate::new_stake_registration(&StakeRegistration::new(&stake_cred)));
        tx_builder.set_certs(&certs);

        let result = tx_builder.add_change_if_needed(
            &change_address
        );
        let expected = Err(String::from("Insufficient input in transaction"));
        assert_eq!(expected, result);
    }
}
