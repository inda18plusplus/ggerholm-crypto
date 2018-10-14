import json
import socket
import time
from threading import Thread

import nacl.secret
import nacl.signing
import nacl.utils
from nacl.encoding import HexEncoder
from nacl.public import Box, PublicKey

from file import File, file_from_json, file_to_json
from merkle import MerkleTree
from socket_protocol import send_message, receive_message, generate_keys, ConnectionManager


class Client(ConnectionManager):
    _latest_top_hash = None

    def __init__(self):
        super().__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # TODO: Remove temporary threading solution
    def start(self):
        t = Thread(target=self.run)
        t.start()

    def run(self):
        self.connect_to_host('localhost', 12317)
        time.sleep(0.5)
        self.setup_secure_channel()
        self.send_bytes(bytes('Hej jag är hemlig data.', encoding='utf-8'))

        self.send_file(File(0, 'Secret file #0'))
        self.send_file(File(5, 'Secret file #5'))
        print('Client: Received ', self.receive_file().__dict__)
        time.sleep(0.5)
        self.send_file(File(2, 'Secret file #2'))
        print('Client: Received ', self.receive_file().__dict__)

    def connect_to_host(self, host, port):
        self.socket.connect((host, port))
        print('Client: Server connection established.')

        # Send our verification hex
        send_message(self.socket, self.verify_key_hex)

        # Receive the server's verification hex
        server_key_hex = receive_message(self.socket)
        if not server_key_hex:
            return False
        self._connection_verify_key = nacl.signing.VerifyKey(server_key_hex, encoder=HexEncoder)
        return True

    def setup_secure_channel(self):
        # Generate our private / public key pair
        private_key, public_key = generate_keys()
        public_key = public_key.encode(encoder=HexEncoder)
        print('Client: Keys generated.')

        # Send our public key to the server
        send_message(self.socket, self._sign_data(public_key))
        print('Client: Public key sent.')

        # Receive the server's public key
        server_public_key = receive_message(self.socket)
        server_public_key = self._verify_sender(server_public_key)
        if not server_public_key:
            return False
        server_public_key = PublicKey(server_public_key, encoder=HexEncoder)
        print('Client: Server public key received.')

        # Receive the secret key generated by the server
        box = Box(private_key, server_public_key)
        secret_key = receive_message(self.socket)
        secret_key = self._verify_sender(secret_key)
        if not secret_key:
            return False
        print('Client: Secret key received.')

        # Setup symmetric encryption using the secret key
        secret_key = box.decrypt(secret_key)
        self._set_secret_key(secret_key)
        return True

    def send_file(self, file):
        file_json = file_to_json(file)
        self.send_bytes(bytes(file_json, encoding='utf-8'))
        top_hash = receive_message(self.socket)
        encrypted = self._verify_sender(top_hash)
        if not encrypted:
            return False
        decrypted = self._decrypt_data(encrypted)
        if not decrypted:
            return False

        self._latest_top_hash = decrypted
        print('Client: Received top hash:', self._latest_top_hash)
        return True

    def receive_file(self):
        file_json = self.receive_bytes()
        if not file_json:
            return None
        file = file_from_json(file_json.decode('utf-8'))
        hash_json = self.receive_bytes()
        hashes = json.loads(hash_json.decode('utf-8'))

        merkle_tree = MerkleTree(foundation=hashes)
        merkle_tree.add_file(file)
        if not merkle_tree.top_node.node_hash == self._latest_top_hash:
            return None

        return file
