MINING_REWARD = 10

# Transaction class to handle transactions
class Transaction:
    def __init__(self, sender, recipient, amount, signature):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'signature': self.signature
        }

    def __repr__(self):
        return str(self.__dict__)

# Block class to handle individual blocks
class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, proof, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = [tx.to_dict() for tx in transactions]
        self.proof = proof
        self.hash = hash

    def __repr__(self):
        return str(self.__dict__)

# Blockchain class to handle blockchain operations
class Blockchain:
    def __init__(self):
        self.transaction_pool = []
        self.chain = []
        self.chain.append(self.create_genesis_block())
        self.nodes = set()

    def create_genesis_block(self):
        return Block(0, "0", int(time.time()), [], 0, "")

    def add_transaction(self, sender, recipient, amount, signature):
        transaction = Transaction(sender, recipient, amount, signature)
        if self.verify_transaction_signature(transaction) and self.verify_transaction(transaction.to_dict()):
            self.transaction_pool.append(transaction)
            if sender != 'MINING':
                return len(self.chain) + 1
        return False

    def verify_transaction_signature(self, transaction):
        public_key = RSA.importKey(binascii.unhexlify(transaction.sender))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA256.new(str(transaction.to_dict()).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(transaction.signature))

    def add_node(self, node):
        parsed_url = urlparse(node)
        self.nodes.add(parsed_url.netloc)
        
    def add_peer_node(self, node):
        parsed_url = urlparse(node)
        self.nodes.add(parsed_url.netloc)
        
    def remove_peer_node(self, node):
        parsed_url = urlparse(node)
        self.nodes.discard(parsed_url.netloc)

    def valid_proof(self, last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def proof_of_work(self):
        last_block = self.chain[-1]
        last_proof = last_block.proof
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    def create_new_block(self, proof, miner_address):
        miner_transaction = Transaction('MINING', miner_address, MINING_REWARD, '')
        self.transaction_pool.append(miner_transaction)
        block = Block(len(self.chain), self.hash(self.chain[-1]), time.time(),
                      list(self.transaction_pool), proof, self.hash(self.chain[-1]))

        self.transaction_pool = []  # Reset the transaction pool
        self.chain.append(block)
        return block

    def hash(self, block):
        encoded_block = json.dumps(block.__dict__, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction['sender'] == address:
                    balance -= transaction['amount']
                elif transaction['recipient'] == address:
                    balance += transaction['amount']
        # Add mining rewards to balance
        balance += MINING_REWARD * sum(tx['recipient'] == address for block in self.chain for tx in block.transactions)
        return balance

    def verify_transaction(self, transaction):
        sender_balance = self.get_balance(transaction['sender'])
        return sender_balance >= transaction['amount']

    def validate_chain(self):
        for i in range(1, len(self.chain)):
            if self.chain[i].index != i:
                print("Index not matching")
                return False
            elif self.chain[i].previous_hash != self.hash(self.chain[i-1]):
                print("Hash not matching")
                return False
        return True
    
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.validate_chain(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False
    
    def get_open_transactions(self):
            return self.transaction_pool

    def save_data(self):
        try:
            with open('blockchain.txt', mode='bw') as f:
                save_data = {
                    'chain': blockchain.chain,
                    'transaction_pool': blockchain.transaction_pool
                }
                f.write(pickle.dumps(save_data))
                return True
        except Exception as e:
            print(str(e))
            return False

    def load_data(self):
        try:
            with open('blockchain.txt', mode='br') as f:
                load_data = pickle.loads(f.read())
                self.chain = load_data['chain']
                self.transaction_pool = load_data['transaction_pool']
                return True
        except Exception as e:
            print(str(e))
            return False

# Wallet class to handle wallet operations
class Wallet:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def create_keys(self):
        private_key, public_key = self.generate_keys()
        self.private_key = private_key
        self.public_key = public_key

    def generate_keys(self):
        private_key = RSA.generate(1024, Crypto.Random.new().read)
        public_key = private_key.publickey()
        return (binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
                binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii'))
    
    def load_keys(self):
            try:
                with open('wallet.txt', mode='r') as f:
                    keys = f.readlines()
                    public_key = keys[0][:-1]
                    private_key = keys[1]
                    self.public_key = public_key
                    self.private_key = private_key
            except (IOError, IndexError):
                print('Loading wallet failed...')
                return False
            
    def save_keys(self):
        if self.public_key is not None and self.private_key is not None:
            try:
                with open('wallet.txt', mode='w') as f:
                    f.write(self.public_key)
                    f.write('\n')
                    f.write(self.private_key)
                return True
            except (IOError, IndexError):
                print('Saving keys failed...')
                return False

    def create_transaction(self, recipient, amount):
        if self.public_key == None:
            print('No public key')
            return False
        transaction = Transaction(self.public_key, recipient, amount, None)
        transaction.signature = self.sign_transaction(transaction)
        return transaction

    def sign_transaction(self, transaction):
        signer = PKCS1_v1_5.new(RSA.importKey(binascii.unhexlify(self.private_key)))
        h = SHA256.new(str(transaction.to_dict()).encode('utf8'))
        signature = signer.sign(h)
        return binascii.hexlify(signature).decode('ascii')

blockchain = Blockchain()
wallet = Wallet()

# Function to get user choice
def get_user_choice():
    return input('Your choice: ')

# Returns the input of the user (a new transaction amount) as a float
def get_transaction_value():
    tx_recipient = input('Enter the recipient of the transaction: ')
    tx_amount = float(input('Your transaction amount please: '))
    return (tx_recipient, tx_amount)

def print_open_transactions():
    if len(blockchain.transaction_pool) > 0:
        print('Open transactions:')
        for tx in blockchain.transaction_pool:
            print(tx)
    else:
        print('No open transactions.')

# Function to print blockchain elements
def print_blockchain_elements():
    for block in blockchain.chain:
        print('Outputting Block')
        print(block)

# Main loop to listen for user input
def listen_for_input():
    while True:
        print('Please choose:')
        print('1:  Add a new transaction')
        print('2:  Mine a new block')
        print('3:  Output the blockchain blocks')
        print('4:  Check transaction validity')
        print('5:  Create wallet')
        print('6:  Load wallet')
        print('7:  Save keys')
        print('8:  Add peer nodes')
        print('9:  Remove peer nodes')
        print('10: Replace chain')
        print('q:  Quit')
        print('\n')
        user_choice = get_user_choice()
        print('\n')
        if user_choice == '1':
            if wallet.public_key is not None:
                tx_data = get_transaction_value()
                transaction = wallet.create_transaction(tx_data[0], tx_data[1])
                if transaction and blockchain.add_transaction(transaction.sender, transaction.recipient, transaction.amount, transaction.signature):
                    print('Added transaction')
                else:
                    print('Transaction failed')
                print_open_transactions()
            else:
                print('No wallet found. Please create a wallet first.')
        elif user_choice == '2':
            blockchain.create_new_block(blockchain.proof_of_work(), wallet.public_key)
        elif user_choice == '3':
            print_blockchain_elements()
        elif user_choice == '4':
            if verify_transactions():
                print('All transactions are valid')
            else:
                print('There are invalid transactions')
        elif user_choice == '5':
            wallet.create_keys()
        elif user_choice == '6':
            wallet.load_keys()
        elif user_choice == '7':
            wallet.save_keys()
        elif user_choice == '8':
            peer_node = input('Enter peer node address: ')
            blockchain.add_peer_node(peer_node)
        elif user_choice == '9':
            peer_node = input('Enter peer node address: ')
            blockchain.remove_peer_node(peer_node)
        elif user_choice == '10':
            blockchain.replace_chain()
        elif user_choice == 'q':
            break
        else:
            print('Input was invalid, please pick a value from the list!\n')
        print('\n')

# Function to verify transactions
def verify_transactions():
    return all([blockchain.verify_transaction_signature(tx) for tx in blockchain.get_open_transactions()])


# Main execution
listen_for_input()
