# import hashlib

# class Block:
# 	def __init__(self, data, previous_hash):
# 		"""
# 		Initializes a new Block object with
# 		the given data and previous hash.
# 		"""
# 		self.data = data
# 		self.previous_hash = previous_hash
# 		self.nonce = 0
# 		self.difficulty = "0000ffff00000000000000000000000000000000000000000000000000000000"
# 		self.hash = self.calculate_hash()

# def calculate_hash(self):
# 	"""
# 	Calculates the SHA-256 hash of the
# 	block's data, previous hash, and nonce.
# 	"""
# 	sha = hashlib.sha256()
# 	sha.update(str(self.data).encode('utf-8') +
# 			str(self.previous_hash).encode('utf-8') +
# 			str(self.nonce).encode('utf-8'))
# 	return sha.hexdigest()

# 	def mine_block(self):
# 		"""
# 		Mines the block using the Proof-of-Work algorithm
# 		with the given difficulty level.
# 		"""
# 		while int(self.hash, 16) > int(self.difficulty, 16):
# 			self.nonce += 1
# 			self.hash = self.calculate_hash()

# 		print("Block mined:", self.hash)


# block = Block("Transaction data 1", "")
# block.mine_block()

# hexadecimal to int
# print(int("ffff001f", 16))
import hashlib

# txid = "13c644c4dbacee307d30d6719879ffa546756aaaa3b29d1125382ecb46474b1a"
# # reverse the string
# txid = hashlib.sha256(txid.encode()).hexdigest()
# print(txid)

# trasaction_data = {
#     "version": 1,
#     "locktime": 0,
#     "vin": [
#         {
#             "txid": "6f01dbfedc8ca4c172ec4e3ac7658d6a195dfd6472067ceb2f7846471b7415b8",
#             "vout": 2,
#             "prevout": {
#                 "scriptpubkey": "76a9141fe2de41946c80a5d3c56ac886997cc471b9ab8188ac",
#                 "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 1fe2de41946c80a5d3c56ac886997cc471b9ab81 OP_EQUALVERIFY OP_CHECKSIG",
#                 "scriptpubkey_type": "p2pkh",
#                 "scriptpubkey_address": "13ubj2SSDWnCP234Bx1rix8qSk9LhQort3",
#                 "value": 160356,
#             },
#             "scriptsig": "4830450221008ba6a3f087256b15f0dfc967c079863e1304fb61fe607744287911e7240aa4e302200801b64bd5f3473e274992b5814c5ea993f5062a8a1c6170f33c0297b29cdf66012102aee96f8d3e0abaf0759a434c7e5a0c9dd1ea89c99bec10605b27779414da80d9",
#             "scriptsig_asm": "OP_PUSHBYTES_72 30450221008ba6a3f087256b15f0dfc967c079863e1304fb61fe607744287911e7240aa4e302200801b64bd5f3473e274992b5814c5ea993f5062a8a1c6170f33c0297b29cdf6601 OP_PUSHBYTES_33 02aee96f8d3e0abaf0759a434c7e5a0c9dd1ea89c99bec10605b27779414da80d9",
#             "is_coinbase": False,
#             "sequence": 4294967295,
#         }
#     ],
#     "vout": [
#         {
#             "scriptpubkey": "6a21134f45a2b88029aa1784d2355e761091a5264426f50737d224b01ddeecab4be1c5",
#             "scriptpubkey_asm": "OP_RETURN OP_PUSHBYTES_33 134f45a2b88029aa1784d2355e761091a5264426f50737d224b01ddeecab4be1c5",
#             "scriptpubkey_type": "op_return",
#             "value": 0,
#         },
#         {
#             "scriptpubkey": "0014419854753506f2b3e771860f36eb919d89cc890f",
#             "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 419854753506f2b3e771860f36eb919d89cc890f",
#             "scriptpubkey_type": "v0_p2wpkh",
#             "scriptpubkey_address": "bc1qgxv9gaf4qmet8em3sc8nd6u3nkyuezg0cg9p36",
#             "value": 1111,
#         },
#         {
#             "scriptpubkey": "76a9141fe2de41946c80a5d3c56ac886997cc471b9ab8188ac",
#             "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 1fe2de41946c80a5d3c56ac886997cc471b9ab81 OP_EQUALVERIFY OP_CHECKSIG",
#             "scriptpubkey_type": "p2pkh",
#             "scriptpubkey_address": "13ubj2SSDWnCP234Bx1rix8qSk9LhQort3",
#             "value": 155388,
#         },
#     ],
# }

trasaction_data = {
    "version": 2,
    "locktime": 0,
    "vin": [
        {
            "txid": "fb7fe37919a55dfa45a062f88bd3c7412b54de759115cb58c3b9b46ac5f7c925",
            "vout": 1,
            "prevout": {
                "scriptpubkey": "76a914286eb663201959fb12eff504329080e4c56ae28788ac",
                "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 286eb663201959fb12eff504329080e4c56ae287 OP_EQUALVERIFY OP_CHECKSIG",
                "scriptpubkey_type": "p2pkh",
                "scriptpubkey_address": "14gnf7L2DjBYKFuWb6iftBoWE9hmAoFbcF",
                "value": 433833,
            },
            "scriptsig": "4830450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd012102c371793f2e19d1652408efef67704a2e9953a43a9dd54360d56fc93277a5667d",
            "scriptsig_asm": "OP_PUSHBYTES_72 30450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd01 OP_PUSHBYTES_33 02c371793f2e19d1652408efef67704a2e9953a43a9dd54360d56fc93277a5667d",
            "is_coinbase": False,
            "sequence": 4294967295,
        }
    ],
    "vout": [
        {
            "scriptpubkey": "76a9141ef7874d338d24ecf6577e6eadeeee6cd579c67188ac",
            "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 1ef7874d338d24ecf6577e6eadeeee6cd579c671 OP_EQUALVERIFY OP_CHECKSIG",
            "scriptpubkey_type": "p2pkh",
            "scriptpubkey_address": "13pjoLcRKqhzPCbJgYW77LSFCcuwmHN2qA",
            "value": 387156,
        },
        {
            "scriptpubkey": "76a9142e391b6c47778d35586b1f4154cbc6b06dc9840c88ac",
            "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 2e391b6c47778d35586b1f4154cbc6b06dc9840c OP_EQUALVERIFY OP_CHECKSIG",
            "scriptpubkey_type": "p2pkh",
            "scriptpubkey_address": "15DQVhQ7PU6VPsTtvwLxfDsTP4P6A3Z5vP",
            "value": 37320,
        },
    ],
}


def calculate_hash(data):

    # version and locktime to 4 bytes
    concat = str(data["version"].to_bytes(4, byteorder="little").hex())
    # length of vin
    concat += str(len(data["vin"]).to_bytes(1, byteorder="big").hex())
    # concat += str(data["vin"][0]["txid"])
    # reversed txid by 2 digits
    # c925 = 25c9
    concat += str(data["vin"][0]["txid"][62:64])
    concat += str(data["vin"][0]["txid"][60:62])
    concat += str(data["vin"][0]["txid"][58:60])
    concat += str(data["vin"][0]["txid"][56:58])
    concat += str(data["vin"][0]["txid"][54:56])
    concat += str(data["vin"][0]["txid"][52:54])
    concat += str(data["vin"][0]["txid"][50:52])
    concat += str(data["vin"][0]["txid"][48:50])
    concat += str(data["vin"][0]["txid"][46:48])
    concat += str(data["vin"][0]["txid"][44:46])
    concat += str(data["vin"][0]["txid"][42:44])
    concat += str(data["vin"][0]["txid"][40:42])
    concat += str(data["vin"][0]["txid"][38:40])
    concat += str(data["vin"][0]["txid"][36:38])
    concat += str(data["vin"][0]["txid"][34:36])
    concat += str(data["vin"][0]["txid"][32:34])
    concat += str(data["vin"][0]["txid"][30:32])
    concat += str(data["vin"][0]["txid"][28:30])
    concat += str(data["vin"][0]["txid"][26:28])
    concat += str(data["vin"][0]["txid"][24:26])
    concat += str(data["vin"][0]["txid"][22:24])
    concat += str(data["vin"][0]["txid"][20:22])
    concat += str(data["vin"][0]["txid"][18:20])
    concat += str(data["vin"][0]["txid"][16:18])
    concat += str(data["vin"][0]["txid"][14:16])
    concat += str(data["vin"][0]["txid"][12:14])
    concat += str(data["vin"][0]["txid"][10:12])
    concat += str(data["vin"][0]["txid"][8:10])
    concat += str(data["vin"][0]["txid"][6:8])
    concat += str(data["vin"][0]["txid"][4:6])
    concat += str(data["vin"][0]["txid"][2:4])
    concat += str(data["vin"][0]["txid"][0:2])

    print(concat)
    concat += str(data["vin"][0]["vout"].to_bytes(4, byteorder="little").hex())
    # concat += "00"
    concat += (len(data["vin"][0]["scriptsig"])//2).to_bytes(1, byteorder="big").hex()
    concat += str(data["vin"][0]["scriptsig"])
    concat += str(data["vin"][0]["sequence"].to_bytes(4, byteorder="big").hex())

    # concat += str(len(data["vin"][0]["witness"]).to_bytes(1, byteorder="big").hex())
    concat += (len(data["vout"])).to_bytes(1, byteorder="big").hex()
    for i in range(len(data["vout"])):
        value = (data["vout"][i]["value"].to_bytes(8, byteorder="big").hex())
        #reverse the value
        value = value[14:16] + value[12:14] + value[10:12] + value[8:10] + value[6:8] + value[4:6] + value[2:4] + value[0:2]
        concat += value
        concat += (len(data["vout"][i]["scriptpubkey"])//2).to_bytes(1, byteorder="big").hex()
        concat += data["vout"][i]["scriptpubkey"]

    concat += str(data["locktime"].to_bytes(4, byteorder="little").hex())
    print(concat)

    # get filename from serialized data
	# hash256 your transaction to get the txid then reverse the txid and sha256 it again
    hash = hashlib.sha256(hashlib.sha256(concat.encode()).hexdigest().encode()).hexdigest()
    print(hash)
    # reverse the bytes order
    hash = hash[62:64] + hash[60:62] + hash[58:60] + hash[56:58] + hash[54:56] + hash[52:54] + hash[50:52] + hash[48:50] + hash[46:48] + hash[44:46] + hash[42:44] + hash[40:42] + hash[38:40] + hash[36:38] + hash[34:36] + hash[32:34] + hash[30:32] + hash[28:30] + hash[26:28] + hash[24:26] + hash[22:24] + hash[20:22] + hash[18:20] + hash[16:18] + hash[14:16] + hash[12:14] + hash[10:12] + hash[8:10] + hash[6:8] + hash[4:6] + hash[2:4] + hash[0:2]
    # hash = hash[::-1]

    hash = hashlib.sha256(hash.encode()).hexdigest()
    print(hash)
    return hash

filename = "fb7fe37919a55dfa45a062f88bd3c7412b54de759115cb58c3b9b46ac5f7c925"
print(hashlib.sha256(hashlib.sha256(hashlib.sha256(filename.encode()).hexdigest().encode()).hexdigest().encode()).hexdigest())

(calculate_hash(trasaction_data))
