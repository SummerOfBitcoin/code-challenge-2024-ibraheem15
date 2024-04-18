import os
import json
import hashlib

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


def mine_block(transactions, difficulty_target):
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
    valid_transactions = [coinbase_transaction] + transactions

    # Calculate the total size of the transactions
    total_size = sum([len(json.dumps(tx)) for tx in valid_transactions])

    # Create a block header
    block_header = hashlib.sha256(
        (str(valid_transactions) + difficulty_target).encode()
    ).hexdigest()

    # Mine the block
    nonce = 0
    while int(block_header, 16) > int(difficulty_target, 16):
        nonce += 1
        block_header = hashlib.sha256(
            (str(valid_transactions) + str(nonce)).encode()
        ).hexdigest()

    # Calculate the fee collected
    fee_collected = sum([tx["vin_value"] - tx["vout_value"] for tx in transactions])

    # Calculate the score
    score = (fee_collected / total_size) * 100
    print(f"Score: {score}")

    # Check if the score is at least 60
    if score < 60:
        print("Score is less than 60")
        return None

    # Create a block
    block = {
        "header": block_header,
        "coinbase": json.dumps(coinbase_transaction),
        "txids": [coinbase_transaction["vin"][0]["txid"]]
        + [tx["txid"] for tx in transactions[1:]],
    }

    return block


def main():
    # Read transactions from mempool
    mempool_path = "mempool"
    transactions = read_transactions(mempool_path)

    # Mine a block
    difficulty_target = (
        "0000ffff00000000000000000000000000000000000000000000000000000000"
    )
    block = mine_block(transactions, difficulty_target)

    # Check if the block is valid
    if block is None:
        print("Block is invalid")
        return

    # Write the block to output.txt
    with open("output.txt", "w") as f:
        f.write(block["header"] + "\n")
        f.write(block["coinbase"] + "\n")
        f.write("\n".join(block["txids"]))


if __name__ == "__main__":
    main()
