# SOLUTION.md

## Design Approach

The block construction program is designed to create a valid block of transactions for a Bitcoin-like cryptocurrency. The program takes a set of unconfirmed transactions from the memory pool (mempool), validates them, and selects a subset of these transactions to include in the block. The selection is based on the transactions' fees and sizes, aiming to maximize the total fee while keeping the block size below the maximum limit.

Key concepts in creating a valid block include:

1. **Transaction Validation**: Each transaction is validated to ensure it adheres to the cryptocurrency's rules. This includes checking the transaction's structure, the sum of its input and output values, and its digital signature.

2. **Transaction Selection**: Transactions are selected based on their fees and sizes. The fee is the difference between the sum of the input values and the sum of the output values. The score is calculated as the fee divided by the transaction size. Transactions with higher scores are prioritized.

3. **Block Creation**: A block is created by combining the selected transactions with a block header. The block header contains the version, previous block hash, Merkle root, timestamp, difficulty target (bits), and nonce.

4. **Block Mining**: The block is mined by adjusting the nonce in the block header and hashing it until the resulting hash is below the difficulty target.

    4.1 **Merkle Root**: The Merkle root is calculated by hashing pairs of transaction hashes until a single hash remains. This root is included in the block header.   

    4.2 **Difficulty Target**: The difficulty target is a number that determines the difficulty of mining a block. The hash of the block header must be below this target to be considered valid.

    4.3 **Nonce**: The nonce is a number that is adjusted to mine the block. The miner increments the nonce and hashes the block header until the resulting hash is below the difficulty target.

    4.4 **Coinbase Transaction**: A special transaction called the coinbase transaction is included in the block. This transaction creates new coins and awards them to the miner of the block. It is the first transaction in the block.
    And it is set as default in the code.

    4.4.1 **Coinbase Transaction Output**: The coinbase transaction has a double output. The second output is the *merkle root* of the wTXIDs of the selected transactions.

## Implementation Details

Here is a high-level pseudo code of the implementation:

```
1. Read transactions from mempool
2. For each transaction, validate the transaction
3. Calculate the fee and score for each transaction
4. Sort transactions by score
5. Select transactions that maximize the score while keeping the total fee below the max-fee limit
6. Create a block header with the selected transactions
7. Mine the block by adjusting the nonce and hashing the block header until the resulting hash is below the difficulty target
8. Create a block with the block header and the selected transactions
9. Create a coinbase transaction with the merkle root of the selected transactions
10. Write the included transactions to the output file
```

Key variables used in the implementation include:

- `transactions`: A list of transaction dictionaries read from the mempool.
- `coinbase_transaction`: A special transaction that creates new coins and awards them to the miner of the block.
- `valid_transactions`: A list of selected transactions to include in the block.
- `prev_block_hash`: The hash of the previous block.
- `merkle_root`: The Merkle root of the selected transactions.
- `timestamp`: The current time.
- `bits`: The difficulty target encoded as a compact integer.
- `nonce`: A number that is adjusted to mine the block.
- `block_header`: A dictionary containing the version, previous block hash, Merkle root, timestamp, difficulty target, and nonce.
- `block`: A dictionary containing the block header and the selected transactions.

## Results and Performance

The program successfully creates a valid block of transactions. The block header hash is below the difficulty target, indicating that the block has been mined. The total fee of the selected transactions is maximized while keeping the block size below the maximum limit.

The efficiency of the solution could be improved by using a more sophisticated algorithm for transaction selection. For example, a knapsack algorithm could be used to select transactions that maximize the total fee while keeping the total size below the block size limit.

## Conclusion

The block construction program provides a practical implementation of the key concepts in a Bitcoin-like cryptocurrency. The program demonstrates how to validate transactions, select transactions based on their fees and sizes, create a block header, mine a block, and create a block.

Potential areas for future improvement or research include:

- Implementing a more efficient algorithm for transaction selection.
- Adding support for Segregated Witness (SegWit) transactions, which separate the transaction signature from the transaction data, allowing more transactions to fit in a block.
- Implementing a more sophisticated block mining algorithm, such as ASIC-resistant proof-of-work.

### References

- Learn Me A Bitcoin: [https://learnmeabitcoin.com/](https://learnmeabitcoin.com/)
    - Coinbase: [https://learnmeabitcoin.com/glossary/coinbase](https://learnmeabitcoin.com/glossary/coinbase)
    - Transactions: [https://learnmeabitcoin.com/transactions/](https://learnmeabitcoin.com/transactions/)
