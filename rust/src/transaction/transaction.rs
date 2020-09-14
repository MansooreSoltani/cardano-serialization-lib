use cbor_event::{se::Serializer, se::Serialize, de::Deserializer};
use crate::serialization::{DeserializeError, Deserialize, DeserializeFailure, DeserializeEmbeddedGroup};
use crate::transaction::{TransactionBody, TransactionWitnessSet, TransactionMetadata};
use std::io::{Write, BufRead, Seek};
use crate::{to_from_bytes, to_bytes, from_bytes};

#[derive(Clone)]
pub struct Transaction {
    pub (crate) body: TransactionBody,
    pub (crate) witness_set: TransactionWitnessSet,
    pub (crate) metadata: Option<TransactionMetadata>,
}

impl Transaction {
    pub fn new(
        body: &TransactionBody,
        witness_set: &TransactionWitnessSet,
        metadata: Option<TransactionMetadata>,
    ) -> Self {
        Self {
            body: body.clone(),
            witness_set: witness_set.clone(),
            metadata: metadata.clone(),
        }
    }
    pub fn body(&self) -> TransactionBody {
        self.body.clone()
    }
    pub fn witness_set(&self) -> TransactionWitnessSet {
        self.witness_set.clone()
    }
    pub fn metadata(&self) -> Option<TransactionMetadata> {
        self.metadata.clone()
    }
}

to_from_bytes!(Transaction);

impl cbor_event::se::Serialize for Transaction {
    fn serialize<'se, W: Write>(&self, serializer: &'se mut Serializer<W>) -> cbor_event::Result<&'se mut Serializer<W>> {
        serializer.write_array(cbor_event::Len::Len(3))?;
        self.body.serialize(serializer)?;
        self.witness_set.serialize(serializer)?;
        match &self.metadata {
            Some(x) => {
                x.serialize(serializer)
            },
            None => serializer.write_special(cbor_event::Special::Null),
        }?;
        Ok(serializer)
    }
}

impl Deserialize for Transaction {
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
        })().map_err(|e| e.annotate("Transaction"))
    }
}

impl DeserializeEmbeddedGroup for Transaction {
    fn deserialize_as_embedded_group<R: BufRead + Seek>(raw: &mut Deserializer<R>, _len: cbor_event::Len) -> Result<Self, DeserializeError> {
        let body = (|| -> Result<_, DeserializeError> {
            Ok(TransactionBody::deserialize(raw)?)
        })().map_err(|e| e.annotate("body"))?;
        let witness_set = (|| -> Result<_, DeserializeError> {
            Ok(TransactionWitnessSet::deserialize(raw)?)
        })().map_err(|e| e.annotate("witness_set"))?;
        let metadata = (|| -> Result<_, DeserializeError> {
            Ok(match raw.cbor_type()? != cbor_event::Type::Special {
                true => {
                    Some(TransactionMetadata::deserialize(raw)?)
                },
                false => {
                    if raw.special()? != cbor_event::Special::Null {
                        return Err(DeserializeFailure::ExpectedNull.into());
                    }
                    None
                }
            })
        })().map_err(|e| e.annotate("metadata"))?;
        Ok(Transaction {
            body,
            witness_set,
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{TransactionInputs, TransactionInput, TransactionOutputs, TransactionOutput, LinearFee, Certificates, Ed25519KeyHashes, PoolRegistration, PoolParams, Relays, Certificate, Withdrawals};
    use crate::crypto::{TransactionHash, Vkeywitnesses, PrivateKey, Vkeywitness, Vkey, BootstrapWitnesses, Bip32PrivateKey, BootstrapWitness, PublicKey, VRFKeyHash, blake2b256};
    use crate::address::{Address, ByronAddress, RewardAddress, StakeCredential};
    use crate::types::{Coin, UnitInterval};

    // based on https://gist.github.com/KtorZ/5a2089df0915f21aca368d12545ab230
    // However, they don't match due to serialization differences in definite vs indefinite
    // CBOR lengths for maps/arrays, thus for now we've got all the tests as >= instead.
    // It's possible they're still off by a byte or two somewhere.

    #[test]
    fn simple_transaction() {
        let mut inputs = TransactionInputs::new();
        let input = TransactionInput::new(
            &TransactionHash::from_bytes(hex::decode("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7").unwrap()).unwrap(),
            0,
        );
        inputs.add(&input);
        let mut outputs = TransactionOutputs::new();
        let output = TransactionOutput::new(
            &Address::from_bytes(hex::decode("611c616f1acb460668a9b2f123c80372c2adad3583b9c6cd2b1deeed1c").unwrap()).unwrap(),
            &1
        );
        outputs.add(&output);
        let fee: Coin = 94_002;
        let ttl = 10;
        let body = TransactionBody::new(&inputs, &outputs, &fee, ttl);

        let address_prvkey = PrivateKey::from_normal_bytes(&hex::decode("c660e50315d76a53d80732efda7630cae8885dfb85c46378684b3c6103e1284a").unwrap()).unwrap();
        let mut witness_set = TransactionWitnessSet::new();
        let mut vkey_witnesses = Vkeywitnesses::new();
        let transaction_hash = body.hash();
        let signature = address_prvkey.sign(transaction_hash.0.as_ref());
        let vkey_witness = Vkeywitness::new(&Vkey::new(&address_prvkey.to_public()), &signature);
        vkey_witnesses.add(&vkey_witness);
        witness_set.set_vkeys(&vkey_witnesses);

        let signed_transaction = Transaction::new(
            &body,
            &witness_set,
            None,
        );

        assert_eq!(
            hex::encode(signed_transaction.to_bytes()),
            "83a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182581d611c616f1acb460668a9b2f123c80372c2adad3583b9c6cd2b1deeed1c01021a00016f32030aa10081825820f9aa3fccb7fe539e471188ccc9ee65514c5961c070b06ca185962484a4813bee5840fae5de40c94d759ce13bf9886262159c4f26a289fd192e165995b785259e503f6887bf39dfa23a47cf163784c6eee23f61440e749bc1df3c73975f5231aeda0ff6"
        );

        let coefficient: Coin = 500;
        let constant: Coin = 2;
        let linear_fee = LinearFee::new(&coefficient, &constant);
        assert_eq!(linear_fee.min_fee(&signed_transaction).unwrap(), fee);
    }

    #[test]
    fn simple_byron_utxo_transaction() {
        let mut inputs = TransactionInputs::new();
        let input = TransactionInput::new(
            &TransactionHash::from_bytes(hex::decode("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7").unwrap()).unwrap(),
            0,
        );
        inputs.add(&input);
        let mut outputs = TransactionOutputs::new();
        let output = TransactionOutput::new(
            &Address::from_bytes(hex::decode("611c616f1acb460668a9b2f123c80372c2adad3583b9c6cd2b1deeed1c").unwrap()).unwrap(),
            &1
        );
        outputs.add(&output);
        let fee: Coin = 112_002;
        let ttl = 10;
        let body = TransactionBody::new(&inputs, &outputs, &fee, ttl);

        let private_key = Bip32PrivateKey::from_bytes(&hex::decode("d84c65426109a36edda5375ea67f1b738e1dacf8629f2bb5a2b0b20f3cd5075873bf5cdfa7e533482677219ac7d639e30a38e2e645ea9140855f44ff09e60c52c8b95d0d35fe75a70f9f5633a3e2439b2994b9e2bc851c49e9f91d1a5dcbb1a3").unwrap()).unwrap();
        let byron_address = ByronAddress::from_base58("Ae2tdPwUPEZ6r6zbg4ibhFrNnyKHg7SYuPSfDpjKxgvwFX9LquRep7gj7FQ").unwrap();
        let mut witness_set = TransactionWitnessSet::new();
        let mut bootstrap_witnesses = BootstrapWitnesses::new();
        let transaction_hash = body.hash();
        let chain_code = private_key.chaincode();
        let raw_private_key = private_key.to_raw();
        let vkey = Vkey::new(&raw_private_key.to_public());
        let signature = raw_private_key.sign(&transaction_hash.to_bytes());
        let bootstrap_witness = BootstrapWitness::new(
            &vkey,
            &signature,
            chain_code,
            byron_address.attributes(),
        );
        bootstrap_witnesses.add(&bootstrap_witness);
        witness_set.set_bootstraps(&bootstrap_witnesses);

        let signed_transaction = Transaction::new(
            &body,
            &witness_set,
            None,
        );

        assert_eq!(
            hex::encode(signed_transaction.to_bytes()),
            "83a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182581d611c616f1acb460668a9b2f123c80372c2adad3583b9c6cd2b1deeed1c01021a0001b582030aa10281845820473811afd4d939b337c9be1a2ceeb2cb2c75108bddf224c5c21c51592a7b204a5840f0b04a852353eb23b9570df80b2aa6a61b723341ab45a2024a05b07cf58be7bdfbf722c09040db6cee61a0d236870d6ad1e1349ac999ec0db28f9471af25fb0c5820c8b95d0d35fe75a70f9f5633a3e2439b2994b9e2bc851c49e9f91d1a5dcbb1a341a0f6"
        );

        let coefficient: Coin = 500;
        let constant: Coin = 2;
        let linear_fee = LinearFee::new(&coefficient, &constant);
        assert_eq!(linear_fee.min_fee(&signed_transaction).unwrap(), fee);
    }

    #[test]
    fn multiple_outputs_and_inputs() {
        let mut inputs = TransactionInputs::new();
        let input1 = TransactionInput::new(
            &TransactionHash::from_bytes(hex::decode("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7").unwrap()).unwrap(),
            42,
        );
        inputs.add(&input1);
        let input2 = TransactionInput::new(
            &TransactionHash::from_bytes(hex::decode("82839f8200d81858248258203b40265111d8bb3c3c608d95b3a0bf83461ace32").unwrap()).unwrap(),
            7,
        );
        inputs.add(&input2);
        let mut outputs = TransactionOutputs::new();
        let output1 = TransactionOutput::new(
            &Address::from_bytes(hex::decode("611c616f1acb460668a9b2f123c80372c2adad3583b9c6cd2b1deeed1c").unwrap()).unwrap(),
            &289
        );
        outputs.add(&output1);
        let output2 = TransactionOutput::new(
            &Address::from_bytes(hex::decode("61bcd18fcffa797c16c007014e2b8553b8b9b1e94c507688726243d611").unwrap()).unwrap(),
            &874_551_452
        );
        outputs.add(&output2);
        let fee: Coin = 183_502;
        let ttl = 999;
        let body = TransactionBody::new(&inputs, &outputs, &fee, ttl);

        let transaction_hash = body.hash();
        assert_eq!(hex::encode(transaction_hash.to_bytes()), "4649b832ee5dab51f3758075fad34f883d8c27841d93cb293c4fe26884179cb3");
        let mut witness_set = TransactionWitnessSet::new();
        let mut vkey_witnesses = Vkeywitnesses::new();

        let private_key1 = PrivateKey::from_normal_bytes(&hex::decode("c660e50315d76a53d80732efda7630cae8885dfb85c46378684b3c6103e1284a").unwrap()).unwrap();
        let signature1 = private_key1.sign(transaction_hash.0.as_ref());
        let vkey_witness1 = Vkeywitness::new(&Vkey::new(&private_key1.to_public()), &signature1);
        vkey_witnesses.add(&vkey_witness1);

        let private_key2 = PrivateKey::from_normal_bytes(&hex::decode("13fe79205e16c09536acb6f0524d04069f380329d13949698c5f22c65c989eb4").unwrap()).unwrap();
        let signature2 = private_key2.sign(transaction_hash.0.as_ref());
        let vkey_witness2 = Vkeywitness::new(&Vkey::new(&private_key2.to_public()), &signature2);
        vkey_witnesses.add(&vkey_witness2);

        witness_set.set_vkeys(&vkey_witnesses);

        let signed_transaction = Transaction::new(
            &body,
            &witness_set,
            None,
        );

        assert_eq!(
            hex::encode(signed_transaction.to_bytes()),
            "83a400828258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7182a82582082839f8200d81858248258203b40265111d8bb3c3c608d95b3a0bf83461ace3207018282581d611c616f1acb460668a9b2f123c80372c2adad3583b9c6cd2b1deeed1c19012182581d61bcd18fcffa797c16c007014e2b8553b8b9b1e94c507688726243d6111a3420989c021a0002ccce031903e7a10082825820f9aa3fccb7fe539e471188ccc9ee65514c5961c070b06ca185962484a4813bee58401ec3e56008650282ba2e1f8a20e81707810b2d0973c4d42a1b4df65b732bda81567c7824904840b2554d2f33861da5d70588a29d33b2b61042e3c3445301d8008258206872b0a874acfe1cace12b20ea348559a7ecc912f2fc7f674f43481df973d92c5840a0718fb5b37d89ddf926c08e456d3f4c7f749e91f78bb3e370751d5b632cbd20d38d385805291b1ef2541b02543728a235e01911f4b400bfb50e5fce589de907f6"
        );

        let coefficient: Coin = 500;
        let constant: Coin = 2;
        let linear_fee = LinearFee::new(&coefficient, &constant);
        assert_eq!(linear_fee.min_fee(&signed_transaction).unwrap(), fee);
    }

    #[test]
    fn with_stake_pool_registration_certificate() {
        let network = 1;
        let mut inputs = TransactionInputs::new();
        let input = TransactionInput::new(
            &TransactionHash::from_bytes(hex::decode("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7").unwrap()).unwrap(),
            0,
        );
        inputs.add(&input);
        let mut outputs = TransactionOutputs::new();
        let output = TransactionOutput::new(
            &Address::from_bytes(hex::decode("611c616f1acb460668a9b2f123c80372c2adad3583b9c6cd2b1deeed1c").unwrap()).unwrap(),
            &1
        );
        outputs.add(&output);
        let fee: Coin = 266_002;
        let ttl = 10;
        let mut body = TransactionBody::new(&inputs, &outputs, &fee, ttl);

        // set up certificates
        let mut certs = Certificates::new();
        let operator = PublicKey::from_bytes(
            &hex::decode("b24c040e65994bd5b0621a060166d32d356ef4be3cc1f848426a4cf386887089").unwrap()
        ).unwrap().hash();
        let vrf_keyhash = VRFKeyHash::from(
            blake2b256(&hex::decode("fbf6d41985670b9041c5bf362b5262cf34add5d265975de176d613ca05f37096").unwrap())
        );
        let pledge = 1_000_000;
        let cost = 1_000_000;
        let margin = UnitInterval::new(
            3,
            100,
        );
        let reward_address = RewardAddress::new(
            network,
            &StakeCredential::from_keyhash(
                &PublicKey::from_bytes(
                    &hex::decode("54d1a9c5ad69586ceeb839c438400c376c0bd34825fb4c17cc2f58c54e1437f3").unwrap()
                ).unwrap().hash()
            ),
        );
        let mut pool_owners = Ed25519KeyHashes::new();
        let pool_owner = PublicKey::from_bytes(
            &hex::decode("54d1a9c5ad69586ceeb839c438400c376c0bd34825fb4c17cc2f58c54e1437f3").unwrap()
        ).unwrap().hash();
        pool_owners.add(&pool_owner);
        let relays = Relays::new();
        let pool_params = PoolParams::new(
            &operator,
            &vrf_keyhash,
            &pledge,
            &cost,
            &margin,
            &reward_address,
            &pool_owners,
            &relays,
            None,
        );
        let registration_cert = PoolRegistration::new(&pool_params);
        certs.add(&Certificate::new_pool_registration(&registration_cert));
        body.set_certs(&certs);

        // set up witness set
        let transaction_hash = body.hash();
        let mut witness_set = TransactionWitnessSet::new();
        let mut vkey_witnesses = Vkeywitnesses::new();
        // input key witness
        let input_private_key = PrivateKey::from_normal_bytes(&hex::decode("c660e50315d76a53d80732efda7630cae8885dfb85c46378684b3c6103e1284a").unwrap()).unwrap();
        let input_key_signature = input_private_key.sign(transaction_hash.0.as_ref());
        let input_vkey_witness = Vkeywitness::new(&Vkey::new(&input_private_key.to_public()), &input_key_signature);
        vkey_witnesses.add(&input_vkey_witness);
        // operator key witness
        let operator_private_key = PrivateKey::from_normal_bytes(&hex::decode("2363f3660b9f3b41685665bf10632272e2d03c258e8a5323436f0f3406293505").unwrap()).unwrap();
        let operator_key_signature = operator_private_key.sign(transaction_hash.0.as_ref());
        let operator_vkey_witness = Vkeywitness::new(&Vkey::new(&operator_private_key.to_public()), &operator_key_signature);
        vkey_witnesses.add(&operator_vkey_witness);
        // owner key witness
        let owner_private_key = PrivateKey::from_normal_bytes(&hex::decode("5ada7f4d92bce1ee1707c0a0e211eb7941287356e6ed0e76843806e307b07c8d").unwrap()).unwrap();
        let owner_key_signature = owner_private_key.sign(transaction_hash.0.as_ref());
        let owner_vkey_witness = Vkeywitness::new(&Vkey::new(&owner_private_key.to_public()), &owner_key_signature);
        vkey_witnesses.add(&owner_vkey_witness);
        witness_set.set_vkeys(&vkey_witnesses);

        let signed_transaction = Transaction::new(
            &body,
            &witness_set,
            None,
        );

        assert_eq!(
            hex::encode(signed_transaction.to_bytes()),
            "83a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182581d611c616f1acb460668a9b2f123c80372c2adad3583b9c6cd2b1deeed1c01021a00040f12030a04818a03581c1c13374874c68016df54b1339b6cacdd801098431e7659b24928efc15820bd0000f498ccacdc917c28274cba51c415f3f21931ff41ca8dc1197499f8e1241a000f42401a000f4240d81e82031864581de151df9ba1b74a1c9608a487e114184556801e927d31d96425cb80af7081581c51df9ba1b74a1c9608a487e114184556801e927d31d96425cb80af7080f6a10083825820f9aa3fccb7fe539e471188ccc9ee65514c5961c070b06ca185962484a4813bee5840a7f305d7e46abfe0f7bea6098bdf853ab9ce8e7aa381be5a991a871852f895a718e20614e22be43494c4dc3a8c78c56cd44fd38e0e5fff3e2fbd19f70402fc02825820b24c040e65994bd5b0621a060166d32d356ef4be3cc1f848426a4cf386887089584013c372f82f1523484eab273241d66d92e1402507760e279480912aa5f0d88d656d6f25d41e65257f2f38c65ac5c918a6735297741adfc718394994f20a1cfd0082582054d1a9c5ad69586ceeb839c438400c376c0bd34825fb4c17cc2f58c54e1437f35840d326b993dfec21b9b3e1bd2f80adadc2cd673a1d8d033618cc413b0b02bc3b7efbb23d1ff99138abd05c398ce98e7983a641b50dcf0f64ed33f26c6e636b0b0ff6"
        );

        let coefficient: Coin = 500;
        let constant: Coin = 2;
        let linear_fee = LinearFee::new(&coefficient, &constant);
        assert_eq!(linear_fee.min_fee(&signed_transaction).unwrap(), 269_002);
    }

    #[test]
    fn with_reward_withdrawal() {
        let mut inputs = TransactionInputs::new();
        let input = TransactionInput::new(
            &TransactionHash::from_bytes(hex::decode("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7").unwrap()).unwrap(),
            0,
        );
        inputs.add(&input);
        let mut outputs = TransactionOutputs::new();
        let output = TransactionOutput::new(
            &Address::from_bytes(hex::decode("611c616f1acb460668a9b2f123c80372c2adad3583b9c6cd2b1deeed1c").unwrap()).unwrap(),
            &1
        );
        outputs.add(&output);
        let fee: Coin = 162_502;
        let ttl = 10;
        let mut body = TransactionBody::new(&inputs, &outputs, &fee, ttl);

        // set up withdrawals
        let mut withdrawals = Withdrawals::new();
        withdrawals.insert(
            &RewardAddress::from_address(&Address::from_bytes(
                hex::decode("e151df9ba1b74a1c9608a487e114184556801e927d31d96425cb80af70").unwrap()
            ).unwrap()).unwrap(),
            &1_337
        );
        body.set_withdrawals(&withdrawals);

        // set up witness set
        let transaction_hash = body.hash();
        let mut witness_set = TransactionWitnessSet::new();
        let mut vkey_witnesses = Vkeywitnesses::new();
        // input key witness
        let input_private_key = PrivateKey::from_normal_bytes(&hex::decode("c660e50315d76a53d80732efda7630cae8885dfb85c46378684b3c6103e1284a").unwrap()).unwrap();
        let input_key_signature = input_private_key.sign(transaction_hash.0.as_ref());
        let input_vkey_witness = Vkeywitness::new(&Vkey::new(&input_private_key.to_public()), &input_key_signature);
        vkey_witnesses.add(&input_vkey_witness);
        // withdrawal key witness
        let withdrawal_private_key = PrivateKey::from_normal_bytes(&hex::decode("5ada7f4d92bce1ee1707c0a0e211eb7941287356e6ed0e76843806e307b07c8d").unwrap()).unwrap();
        let withdrawal_key_signature = withdrawal_private_key.sign(transaction_hash.0.as_ref());
        let withdrawal_vkey_witness = Vkeywitness::new(&Vkey::new(&withdrawal_private_key.to_public()), &withdrawal_key_signature);
        vkey_witnesses.add(&withdrawal_vkey_witness);
        witness_set.set_vkeys(&vkey_witnesses);

        let signed_transaction = Transaction::new(
            &body,
            &witness_set,
            None,
        );

        assert_eq!(
            hex::encode(signed_transaction.to_bytes()),
            "83a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182581d611c616f1acb460668a9b2f123c80372c2adad3583b9c6cd2b1deeed1c01021a00027ac6030a05a1581de151df9ba1b74a1c9608a487e114184556801e927d31d96425cb80af70190539a10082825820f9aa3fccb7fe539e471188ccc9ee65514c5961c070b06ca185962484a4813bee5840fc0493f7121efe385d72830680e735ccdef99c3a31953fe877b89ad3a97fcdb871cc7f2cdd6a8104e52f6963bd9e10d814d4fabdbcdc8475bc63e872dcc94d0a82582054d1a9c5ad69586ceeb839c438400c376c0bd34825fb4c17cc2f58c54e1437f35840a051ba927582004aedab736b9f1f9330ff867c260f4751135d480074256e83cd23d2a4bb109f955c43afdcdc5d1841b28d5c1ea2148dfbb6252693590692bb00f6"
        );

        let coefficient: Coin = 500;
        let constant: Coin = 2;
        let linear_fee = LinearFee::new(&coefficient, &constant);
        assert_eq!(linear_fee.min_fee(&signed_transaction).unwrap(), fee);
    }
}