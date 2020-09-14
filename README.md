# Cardano Serialization Lib

This is a library for serialization & deserialization of data structures used in Cardano's Haskell implementation of
Shelley along with useful utility functions.

# How to build and install

You can install this library named `cardano_serialization_lib` using one of the following two methods.

- Install with setup.py
- Install with cargo build and manual deploy

## Install with setup.py

Run the following script and then you can import `cardano_serialization_lib` module and use it in python.

```shell script
$ python setup.py install
```

## Install with cargo build and manual deploy

```shell script
$ cd rust
# On windows and Linux
$ cargo build --release
# On mac OS
$ cargo rustc --release -- -C link-arg=-undefined -C link-arg=dynamic_lookup
```

**Copy artifacts**

While developing, you can symlink (or copy) and rename the shared library from the target folder:
- On MacOS, rename libcardano_serialization_lib_py.dylib to cardano_serialization_lib.so
- on Windows libcardano_serialization_lib_py.dll to cardano_serialization_lib.pyd
- on Linux libcardano_serialization_lib_py.so to cardano_serialization_lib.so

*e.g. on MacOS*

```shell script
$ ln -s `pwd`/rust/target/release/libcardano_serialization_lib_py.dylib ./cardano_serialization_lib.so
```

# How to run

after installing via `setup.py` or deploying the rust build artifact,
you can import `cardano_serialization_lib` module and use it in python.

see [example.py](./example.py) for usage examples.

```python
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
```
