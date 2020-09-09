# Cardano Serialization Lib

This is a library for serialization & deserialization of data structures used in Cardano's Haskell implementation of
Shelley along with useful utility functions.

# How to build

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

after deploying the rust build artifact, you can import `cardano_serialization_lib` module and use it in python.

see [example.py](./example.py) for usage examples.

```python
import cardano_serialization_lib

phrase = "art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy"
password = ""
network = 0
account = 0
chains = 0
index = 0
address = cardano_serialization_lib.generate_bip32_enterprise_address(phrase, password, network, account, chains, index)
print(address)
```
