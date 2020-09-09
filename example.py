import cardano_serialization_lib

phrase = "art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy"
password = ""
network = 0
account = 0
chains = 0
index = 0
address = cardano_serialization_lib.generate_bip32_enterprise_address(phrase, password, network, account, chains, index)
print(address)
