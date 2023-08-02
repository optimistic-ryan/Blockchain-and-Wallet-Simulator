# Blockchain and Wallet Simulator

This Python project demonstrates a simple implementation of a Blockchain and Wallet system. The Blockchain class contains methods for various operations such as adding transactions, verifying transactions, mining new blocks, and replacing the chain. The Wallet class facilitates the creation and management of private and public keys for secure transactions. 

## Features
- Transaction handling using digital signatures
- Proof-of-work for mining new blocks
- Peer-to-peer network
- Verification of transaction integrity
- Balance calculation for any given address
- Basic wallet functionality with key pair generation and transaction signing

## Code Description
- `Transaction`: This class is responsible for handling individual transactions. It contains the sender's and recipient's details, the amount of the transaction, and a digital signature.
- `Block`: This class handles individual blocks. Each block contains an index, the hash of the previous block, a timestamp, a set of transactions, a proof of work, and its own hash.
- `Blockchain`: This class handles blockchain operations. It contains methods for creating new blocks, validating the blockchain, handling transactions, and managing a peer-to-peer network.
- `Wallet`: This class manages the wallet, which holds the private and public keys of a user. It has methods to create, load, and save keys, as well as to create and sign transactions.
- `listen_for_input`: This function starts a loop that waits for user input and performs actions based on the input.
- `verify_transactions`: This function verifies the validity of all open transactions.

## How to Use
1. Run the Python script. 
2. When prompted, select an option from the displayed menu.
3. If you want to make a transaction, make sure you have created a wallet and loaded it first.
4. You can mine new blocks, check the integrity of transactions, and interact with peer nodes.
