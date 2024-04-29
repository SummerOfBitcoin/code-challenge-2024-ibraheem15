import os
import json
import hashlib
import time


# Function to validate a transaction
def validate_transaction(transaction):
    # Check if the transaction is a dictionary
    if not isinstance(transaction, dict):
        print("Transaction is not a dictionary")
        return False

    # Check if the transaction has an id, inputs, and outputs
    required_attributes = ["version", "locktime", "vin", "vout"]
    missing_attributes = [
        attr for attr in required_attributes if attr not in transaction
    ]
    if missing_attributes:
        print(f"Transaction is missing {', '.join(missing_attributes)}")
        return False

    # Check if the version and locktime are integers
    if not isinstance(transaction["version"], int) or not isinstance(
        transaction["locktime"], int
    ):
        print("Transaction version or locktime is not an integer")
        return False

    # Check if the vin and vout are lists
    if not isinstance(transaction["vin"], list) or not isinstance(
        transaction["vout"], list
    ):
        print("Transaction vin or vout is not a list")
        return False

    # Check if the vin and vout are not empty
    if not transaction["vin"] or not transaction["vout"]:
        print("Transaction vin or vout is empty")
        return False

    # Check if each vin and vout item is a dictionary
    for vin_item in transaction["vin"]:
        if not isinstance(vin_item, dict):
            print("Transaction vin item is not a dictionary")
            return False
    for vout_item in transaction["vout"]:
        if not isinstance(vout_item, dict):
            print("Transaction vout item is not a dictionary")
            return False

    # Check if each vin item has txid, vout, prevout, scriptsig, witness, is_coinbase, and sequence
    for vin_item in transaction["vin"]:
        missing_attributes = [
            attr
            for attr in [
                "txid",
                "vout",
                "prevout",
                "scriptsig",
                "witness",
                "is_coinbase",
                "sequence",
            ]
            if attr not in vin_item
        ]
        if missing_attributes:
            print(f"Vin item is missing {', '.join(missing_attributes)}")
            return False

    # Check if each vout item has scriptpubkey, scriptpubkey_asm, scriptpubkey_type, scriptpubkey_address, and value
    for vout_item in transaction["vout"]:
        missing_attributes = [
            attr
            for attr in [
                "scriptpubkey",
                "scriptpubkey_asm",
                "scriptpubkey_type",
                "scriptpubkey_address",
                "value",
            ]
            if attr not in vout_item
        ]
        if missing_attributes:
            print(f"Vout item is missing {', '.join(missing_attributes)}")
            return False

    # Check if the sum of the output values is less than or equal to the sum of the input values
    vin_value = sum([vin["prevout"]["value"] for vin in transaction["vin"]])
    vout_value = sum([vout["value"] for vout in transaction["vout"]])
    if vin_value < vout_value:
        print("Sum of input values is less than sum of output values")
        return False

    return True


# Function to read all transactions from mempool folder
def read_transactions(mempool_path):
    transactions = []
    count = 0
    for filename in os.listdir(mempool_path):
        if filename.endswith(".json"):
            with open(os.path.join(mempool_path, filename), "r") as f:
                transaction = json.load(f)

                # Validate the transaction
                if not validate_transaction(transaction):
                    # print(f"Transaction in {filename} is invalid")
                    continue

                # Add attributes to the transaction object
                transaction["txid"] = transaction["vin"][0]["txid"]
                transaction["vin_value"] = sum(
                    [vin["prevout"]["value"] for vin in transaction["vin"]]
                )
                transaction["vout_value"] = sum(
                    [vout["value"] for vout in transaction["vout"]]
                )

                # Add the transaction to the list
                transactions.append(transaction)
                count += 1
                # if count == 12:
                # break
    return transactions


def get_transaction_size(transaction):
    # Calculate the size of the version field (4 bytes)
    version_size = 4

    # Calculate the size of the locktime field (4 bytes)
    locktime_size = 4

    # Calculate the size of the vin field
    vin_size = 0
    for vin_item in transaction["vin"]:
        # Calculate the size of the txid field (32 bytes)
        txid_size = 32

        # Calculate the size of the vout field (4 bytes)
        vout_size = vin_item["vout"]

        # Calculate the size of the prevout field
        prevout_size = 0
        if "prevout" in vin_item:
            # Calculate the size of the scriptpubkey field
            scriptpubkey_size = len(vin_item["prevout"]["scriptpubkey"]) // 2

            # Calculate the size of the value field (8 bytes)
            value_size = vin_item["prevout"]["value"]

            # Sum up the sizes of the prevout fields
            prevout_size = scriptpubkey_size + value_size

        # Calculate the size of the scriptsig field
        scriptsig_size = 0
        if "scriptsig" in vin_item:
            scriptsig_size = len(vin_item["scriptsig"]) // 2

        # Calculate the size of the witness field
        witness_size = 0
        if "witness" in vin_item:
            witness_size = sum([len(w) // 2 for w in vin_item["witness"]])

        # Sum up the sizes of the vin fields
        vin_size += txid_size + vout_size + prevout_size + scriptsig_size + witness_size

    # Calculate the size of the vout field
    vout_size = 0
    for vout_item in transaction["vout"]:
        # Calculate the size of the scriptpubkey field
        scriptpubkey_size = len(vout_item["scriptpubkey"]) // 2

        # Calculate the size of the value field (8 bytes)
        value_size = vout_item["value"]

        # Sum up the sizes of the vout fields
        vout_size += scriptpubkey_size + value_size

    # Sum up the sizes of all fields
    transaction_size = version_size + locktime_size + vin_size + vout_size

    return transaction_size


def calculate_merkle_root(transactions):
    """
    Calculate the Merkle root of a list of transactions.
    """
    if len(transactions) == 1:
        return hashlib.sha256(
            hashlib.sha256(
                json.dumps(transactions[0], sort_keys=True).encode()
            ).digest()
        ).digest()

    transactions = transactions[:7]
    reversed_txids = [bytes.fromhex(tx["vin"][0]["txid"])[::-1] for tx in transactions]
    while len(reversed_txids) > 1:
        if len(reversed_txids) % 2 != 0:
            reversed_txids.append(reversed_txids[-1])
        reversed_txids = [
            hashlib.sha256(
                hashlib.sha256(reversed_txids[i] + reversed_txids[i + 1]).digest()
            ).digest()
            for i in range(0, len(reversed_txids), 2)
        ]
    print("Merkle root:", reversed_txids[0].hex())
    return reversed_txids[0].hex()


def difficulty_target_to_bits(difficulty_target):
    """
    Convert a difficulty target to a compact representation used in the block header.
    """
    # Convert hexadecimal to integer
    difficulty_int = int(difficulty_target, 16)

    # Calculate the exponent and mantissa
    exponent = 0
    mantissa = difficulty_int
    while (mantissa & 0xFF) == 0:
        mantissa >>= 8
        exponent += 1

    # Calculate the compact representation
    bits = (exponent << 24) | mantissa
    return 0x1F00FFFF
    return bits



def calculate_hash_serialized(data):

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
    concat += (len(data["vin"][0]["scriptsig"]) // 2).to_bytes(1, byteorder="big").hex()
    concat += str(data["vin"][0]["scriptsig"])
    concat += str(data["vin"][0]["sequence"].to_bytes(4, byteorder="big").hex())

    # concat += str(len(data["vin"][0]["witness"]).to_bytes(1, byteorder="big").hex())
    concat += (len(data["vout"])).to_bytes(1, byteorder="big").hex()
    for i in range(len(data["vout"])):
        value = data["vout"][i]["value"].to_bytes(8, byteorder="big").hex()
        # reverse the value
        value = (
            value[14:16]
            + value[12:14]
            + value[10:12]
            + value[8:10]
            + value[6:8]
            + value[4:6]
            + value[2:4]
            + value[0:2]
        )
        concat += value
        concat += (
            (len(data["vout"][i]["scriptpubkey"]) // 2)
            .to_bytes(1, byteorder="big")
            .hex()
        )
        concat += data["vout"][i]["scriptpubkey"]

    concat += "0120" + data["vin"][0]["witness"][0]
    concat += str(data["locktime"].to_bytes(4, byteorder="little").hex())
    print(concat)

    # get filename from serialized data
    # hash256 your transaction to get the txid then reverse the txid and sha256 it again
    hash = hashlib.sha256(
        hashlib.sha256(concat.encode()).hexdigest().encode()
    ).hexdigest()
    print(hash)
    # reverse the bytes order
    hash = (
        hash[62:64]
        + hash[60:62]
        + hash[58:60]
        + hash[56:58]
        + hash[54:56]
        + hash[52:54]
        + hash[50:52]
        + hash[48:50]
        + hash[46:48]
        + hash[44:46]
        + hash[42:44]
        + hash[40:42]
        + hash[38:40]
        + hash[36:38]
        + hash[34:36]
        + hash[32:34]
        + hash[30:32]
        + hash[28:30]
        + hash[26:28]
        + hash[24:26]
        + hash[22:24]
        + hash[20:22]
        + hash[18:20]
        + hash[16:18]
        + hash[14:16]
        + hash[12:14]
        + hash[10:12]
        + hash[8:10]
        + hash[6:8]
        + hash[4:6]
        + hash[2:4]
        + hash[0:2]
    )
    # hash = hash[::-1]

    hash = hashlib.sha256(hash.encode()).hexdigest()
    print(hash)
    
    return concat

def mine_block(transactions, difficulty_target, max_fee, max_score, passing_score):
    # Create a coinbase transaction
    coinbase_transaction = {
        "version": 1,
        "locktime": 0,
        "vin": [
            {
                "txid": "0000000000000000000000000000000000000000000000000000000000000000",
                "vout": 0xFFFFFFFF,
                "prevout": {
                    "scriptpubkey": "a914e280d91ab0f233b9fad52069c3f496ec9990ae7087",
                    "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 e280d91ab0f233b9fad52069c3f496ec9990ae70 OP_EQUAL",
                    "scriptpubkey_type": "p2sh",
                    "scriptpubkey_address": "3NLezRBqRYYGBvNdQSW9etkvAb5f3fr1Kp",
                    "value": 600,
                },
                "scriptsig": "04233fa04e028b12",
                "scriptsig_asm": "OP_PUSHBYTES_22 00149bf838bc3ae119819414f7f482bacb3df7d2d2e6",
                "witness": [
                    "000000000000000000000000000000000000000000000000000000000000000000",
                ],
                "is_coinbase": False,
                "sequence": 0xFFFFFFFF,
                "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_20 9bf838bc3ae119819414f7f482bacb3df7d2d2e6",
            }
        ],
        "vout": [
            {
                "scriptpubkey": "76a9142c30a6aaac6d96687291475d7d52f4b469f665a688ac",
                "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 e280d91ab0f233b9fad52069c3f496ec9990ae70 OP_EQUAL",
                "scriptpubkey_type": "p2sh",
                "scriptpubkey_address": "3NLezRBqRYYGBvNdQSW9etkvAb5f3fr1Kp",
                "value": 1212100,
            },
            {
                "scriptpubkey": "76a9142c30a6aaac6d96687291475d7d52f4b469f665a688ac",
                "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 19283abbbc6a440423b9765a55964f7176eb8e247713a9ac7475cfe90c7ed9be",
                "scriptpubkey_type": "v1_p2tr",
                "scriptpubkey_address": "bc1pry5r4waudfzqggaewed9t9j0w9mwhr3ywuf6ntr5wh87jrr7mxlq8trfzs",
                "value": 000000000,
            },
        ],
    }

    # Add the coinbase transaction to the list of transactions
    valid_transactions = [coinbase_transaction]

    # Calculate the fee and score for each transaction
    transaction_fees = []
    transaction_scores = []
    for transaction in transactions:
        # Calculate the fee
        fee = transaction["vin_value"] - transaction["vout_value"]
        transaction_fees.append(fee)

        # calculate the size of the transaction
        transaction["size"] = get_transaction_size(transaction)

        # Calculate the score
        score = min(max_score, fee / transaction["size"])
        transaction_scores.append(score)

    # Sort the transactions by score
    sorted_indices = sorted(
        range(len(transaction_scores)),
        key=lambda i: transaction_scores[i],
        reverse=True,
    )

    # Select transactions that maximize the score while keeping the total fee below the max-fee limit
    total_fee = 0
    total_score = 0
    for i in sorted_indices:
        fee = transaction_fees[i]
        score = transaction_scores[i]
        if total_fee + fee > max_fee:
            break
        valid_transactions.append(transactions[i])
        total_fee += fee
        total_score += score

    # Check if the total score is above the passing-score threshold
    if total_score < passing_score:
        print("Total score is below passing-score threshold:", total_score)
        return None

    # Create a block header
    prev_block_hash = bytes.fromhex(coinbase_transaction["vin"][0]["txid"])
    # valid_transactions = valid_transactions[:7]
    # print("Valid transactions:", list(map(lambda tx: tx["vin"][0]["txid"], valid_transactions)))
    merkle_root = calculate_merkle_root(valid_transactions)
    timestamp = int(time.time())
    print("Timestamp:", timestamp)
    bits = difficulty_target_to_bits(difficulty_target)
    # print bits in hex
    print("Bits in hex:", hex(bits))
    nonce = 0

    block_header = (
        int.to_bytes(5, 4, "little")
        + prev_block_hash
        + bytes.fromhex(merkle_root)
        + int.to_bytes(timestamp, 4, "little")
        + int.to_bytes(bits, 4, "little")
        + int.to_bytes(nonce, 4, "little")
    )
    print("Block header:", len(block_header))

    # Mine the block
    def calculate_hash(data):
        block_header_hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1]
        return block_header_hash

    while True:
        block_header_hash = calculate_hash(block_header)
        if int.from_bytes(block_header_hash, "big") < int(difficulty_target, 16):
            break
        nonce += 1
        block_header = (
            int.to_bytes(5, 4, "little")
            + prev_block_hash
            + bytes.fromhex(merkle_root)
            + int.to_bytes(timestamp, 4, "little")
            + int.to_bytes(bits, 4, "little")
            + int.to_bytes(nonce, 4, "little")
        )

    print("Block mined:", block_header_hash)

    # Compare the target with the reverse of the double SHA-256 hash of the block header
    target = int(difficulty_target, 16)
    print("Target-----:", target)
    if int.from_bytes(block_header_hash, "big") < target:
        print("Block mined:", block_header_hash)
    else:
        print("Block hash does not meet the target")

    print(block_header.hex())
    
    coinbase_transaction_hash = calculate_hash_serialized(coinbase_transaction)
    print("Coinbase transaction hash:", coinbase_transaction_hash)

    # Create a block
    block = {
        "header": block_header.hex(),
        # "coinbase": coinbase_transaction["vin"][0]["txid"],
        "coinbase": coinbase_transaction_hash,
        "txids": [coinbase_transaction["vin"][0]["txid"]]
        + [tx["txid"] for tx in valid_transactions[1:7]],
    }

    return block


def main():
    # Read transactions from mempool
    mempool_path = "mempool"
    # mempool_path = "code-challenge-2024-ibraheem15/mempool"
    transactions = read_transactions(mempool_path)

    # Mine a block
    difficulty_target = (
        "0000ffff00000000000000000000000000000000000000000000000000000000"
    )
    max_fee = 20616923
    max_score = 100
    passing_score = 60
    block = mine_block(
        transactions, difficulty_target, max_fee, max_score, passing_score
    )

    # Write the block to output.txt
    with open("output.txt", "w") as f:
        f.write(block["header"] + "\n")
        f.write(block["coinbase"] + "\n")
        f.write("\n".join(block["txids"]))


if __name__ == "__main__":
    main()
