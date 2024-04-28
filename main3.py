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

def mine_nonce(block_header, difficulty_target):
    nonce = 0
    while True:
        # Update the block header with the nonce
        block_header["nonce"] = nonce
        
        # Calculate the block hash
        block_string = json.dumps(block_header, sort_keys=True)
        block_hash = hashlib.sha256(block_string.encode()).hexdigest()
        
        # Check if the block hash meets the difficulty target
        if int(block_hash, 16) < int(difficulty_target, 16):
            print("Block mined with nonce:", nonce)
            print("Block hash:", block_hash)
            return nonce
        
        # Increment the nonce
        nonce += 1
        

def mine_block(transactions, difficulty_target, max_fee, max_score, passing_score):
    # Initialize the block
    block = {
        "header": "",
        "coinbase": "",
        "txids": [],
    }

    # Initialize the block header
    block_header = {
        "version": 1,
        "prev_block": "b9b515b6171b47940809366f5d58591a56063db03fc39f678a03cb2b455f9428",
        "merkle_root": "",
        "timestamp": int(time.time()),
        "bits": difficulty_target,
        "nonce": 0,
    }
    
    # Initialize the coinbase transaction
    coinbase_transaction = {
        "version": 1,
        "locktime": 0,
        "vin": [
            {
                "txid": "b9b515b6171b47940809366f5d58591a56063db03fc39f678a03cb2b455f9428",
                "vout": 0,
                "prevout": {
                    "value": 0,
                    "scriptpubkey": "03e0e5f7b8d0c1d5f7f2",
                },
                "scriptsig": "",
                "witness": "",
                "is_coinbase": True,
                "sequence": 0,
                
            }
        ],
        "vout": [
            {
                "value": 0,
                "scriptpubkey": "03e0e5f7b8d0c1d5f7f2",
                "scriptpubkey_asm": "OP_PUSHBYTES_33 0xe0e5f7b8d0c1d5f7f2",
                "scriptpubkey_type": "pubkey",
                "scriptpubkey_address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            }
        ],
    }
    
    # Calculate the coinbase transaction fee
    coinbase_fee = max_fee
    coinbase_transaction["vout"][0]["value"] = coinbase_fee
    
    # Add the coinbase transaction to the block
    block["coinbase"] = json.dumps(coinbase_transaction, indent=4)
    
    # Add the coinbase transaction ID to the list of transaction IDs
    block["txids"].append(coinbase_transaction["vin"][0]["txid"])
    
    # Calculate the total fee and total score
    total_fee = coinbase_fee
    total_score = 0
    
    # Initialize the list of selected transactions
    selected_transactions = []
    
    print("Total transactions: ", len(transactions))
    # Select transactions with the highest fee and score
    for transaction in transactions:
        # if total_fee + transaction["vin_value"] - transaction["vout_value"] <= max_fee:
            selected_transactions.append(transaction)
            total_fee += transaction["vin_value"] - transaction["vout_value"]
            block["txids"].append(transaction["txid"])
            print(transaction["txid"], " " " ", transaction["vin_value"], " ", transaction["vout_value"])
            if total_score >= passing_score:
                break
            
    # Calculate the merkle root
    merkle_root = hashlib.sha256()
    for txid in block["txids"]:
        merkle_root.update(txid.encode())
        
    # Update the block header with the merkle root
    block_header["merkle_root"] = merkle_root.hexdigest()
    
    # Update the block header with the nonce
    block_header["nonce"] = mine_nonce(block_header, difficulty_target)
    
    # Update the block header in the block
    block["header"] = json.dumps(block_header, indent=4)
    
    #convert block header to bytes
    block_header_bytes = json.dumps(block_header, sort_keys=True).encode()
    # Calculate the block hash
    block_hash = hashlib.sha256(block_header_bytes).hexdigest()
    print("Block hash: ", len(block_hash))
    
    block_header = {
        int.to_bytes(block_header["version"], 4, byteorder='big'),
        block_header["prev_block"].encode(),
        block_header["merkle_root"].encode(),
        int.to_bytes(block_header["timestamp"], 4, byteorder='big'),
        block_header["bits"].encode(),
        int.to_bytes(block_header["nonce"], 4, byteorder='big')
    }
    
    print("Block header: ", block_header)
    
    block["header"] = block_header
    

    return block


def main():
    # Read transactions from mempool
    mempool_path = "code-challenge-2024-ibraheem15/mempool"
    # mempool_path = "mempool"
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
