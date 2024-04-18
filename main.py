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
    print("Transaction ID: ", transaction["vin"][0]["txid"])
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
                    print(f"Transaction in {filename} is invalid")
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
        return hashlib.sha256(hashlib.sha256(json.dumps(transactions[0], sort_keys=True).encode()).digest()).digest()

    hashes = [
        hashlib.sha256(hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).digest()).digest()
        for tx in transactions
    ]
    while len(hashes) > 1:
        new_hashes = []
        for i in range(0, len(hashes), 2):
            if i + 1 < len(hashes):
                new_hashes.append(
                    hashlib.sha256(
                        hashlib.sha256(hashes[i] + hashes[i + 1]).digest()
                    ).digest()
                )
            else:
                new_hashes.append(hashes[i])
        hashes = new_hashes

    return hashes[0]


def difficulty_target_to_bits(difficulty_target):
    """
    Convert a difficulty target to a compact representation used in the block header.
    """
    target_hex = int.from_bytes(bytes.fromhex(difficulty_target), "big")
    exponent = (target_hex >> 24) & 0xff
    mantissa = target_hex & 0x00ffffff
    return (exponent << 24) | mantissa


def mine_block(transactions, difficulty_target, max_fee, max_score, passing_score):
    # Create a coinbase transaction
    coinbase_transaction = {
        "version": 1,
        "locktime": 0,
        "vin": [
            {
                "txid": "0000000000000000000000000000000000000000000000000000000000000000",
                "sequence": 4294967295,
            }
        ],
        "vout": [
            {
                "value": 50,
                "n": 0,
                "scriptPubKey": {
                    "asm": "OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG",
                    "hex": "76a914<pubKeyHash>88ac",
                    "reqSigs": 1,
                    "type": "pubkeyhash",
                    "addresses": ["coinbase"],
                },
            }
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
    merkle_root = calculate_merkle_root(valid_transactions)
    timestamp = int(time.time())
    bits = difficulty_target_to_bits(difficulty_target)
    nonce = 0

    block_header = (
        int.to_bytes(1, 4, "little")
        + prev_block_hash
        + merkle_root
        + int.to_bytes(timestamp, 4, "little")
        + int.to_bytes(bits, 4, "little")
        + int.to_bytes(nonce, 4, "little")
    )
    print("Block header:",len(block_header))

    # Mine the block
    block_header_hash = None
    while block_header_hash is None or block_header_hash > int.from_bytes(
        bytes.fromhex(difficulty_target), "big"
    ):
        nonce += 1
        block_header = (
            int.to_bytes(1, 4, "little")
            + prev_block_hash
            + merkle_root
            + int.to_bytes(timestamp, 4, "little")
            + int.to_bytes(bits, 4, "little")
            + int.to_bytes(nonce, 4, "little")
        )
        block_header_hash = int.from_bytes(
            hashlib.sha256(hashlib.sha256(block_header).digest()).digest(), "big"
        )

    # Create a block
    block = {
        "header": block_header.hex(),
        "coinbase": json.dumps(coinbase_transaction),
        "txids": [coinbase_transaction["vin"][0]["txid"]]
        + [tx["txid"] for tx in valid_transactions[1:]],
    }

    return block


def main():
    # Read transactions from mempool
    mempool_path = "mempool"
    transactions = read_transactions(mempool_path)

    # Mine a block
    difficulty_target = (
        "f7b3c47b07f4ce00d4d499f2742ee026f60ed9854d408a5adaaff337f7bf9fdb"
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
