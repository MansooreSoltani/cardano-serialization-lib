import cardano_serialization_lib

# get bip32 enterprise address string in bech32 format.
phrase = "art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy"
password = ""
network = 0
account = 0
chains = 0
index = 0
address = cardano_serialization_lib.generate_bip32_enterprise_address(phrase, password, network, account, chains, index)
print(address)


# get raw signed transaction bytes
utxo_list = [
    (
        bytes.fromhex("64887f4d5a17571af19c0a73495c17d5dd2627951e50e39ecd7e674621f42d2e"),  # transaction_hash bytes
        0,                                                                                  # transaction_index
        3000000,                                                                            # value
        "addr_test1vpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5eg57c2qv",                  # address
        phrase,                                                                             # bip32_phrase
        password,                                                                           # bip32_password
        account,                                                                            # bip32_account
        chains,                                                                             # bip32_chains
        index                                                                               # bip32_index
    )
]
to_address = "addr_test1vq0a2lgc2e0r597dr983jrf5ns4hxz027u8n7wlcsjcw4ks96yjys"
send_amount = 1000000
ttl = 410000
change_address = "addr_test1vrq9aq9aeun8ull8ha9gv7h72jn95ds9kv42aqcw6plcu8qkyz99l"
tx_str = cardano_serialization_lib.generate_transaction_from_bip32_enterprise_address(
    network,
    utxo_list,
    to_address,
    send_amount,
    ttl,
    change_address,
)
print(tx_str)
