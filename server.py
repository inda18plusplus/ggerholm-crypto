import socket
import time
from threading import Thread

from nacl.encoding import HexEncoder
from nacl.public import Box, PublicKey
from nacl.secret import SecretBox
from nacl.signing import VerifyKey
from nacl.utils import random

from file import file_from_json, file_to_json
from merkle import MerkleTree, node_to_json
from socket_protocol import receive_message, generate_keys, generate_signing_keys, send_message, ConnectionManager


class Server(ConnectionManager):
    files = []

    def __init__(self):
        super().__init__()
        self.address = '127.0.0.1'
        self.port = 12317
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.address, self.port))

        self.signing_key, self.verify_key, self.verify_key_hex = generate_signing_keys()

        self.merkle_tree = MerkleTree(16)

    # TODO: Remove temporary threading solution
    def start(self):
        t = Thread(target=self.run)
        t.start()

    def run(self):
        self.accept_connection()
        self.setup_secure_channel()
        print('Server: Received "', self.receive_bytes().decode('utf-8'), '"', sep='')
        self.receive_file()
        self.receive_file()
        time.sleep(0.5)
        self.send_file(5)
        self.receive_file()
        time.sleep(0.5)
        self.send_file(0)

    def accept_connection(self):
        self.server_socket.listen(5)
        self.socket, address = self.server_socket.accept()
        print('Server: Client connected from', address)

        # Receive the client's verification hex
        client_key_hex = receive_message(self.socket)
        if not client_key_hex:
            return False
        self._connection_verify_key = VerifyKey(client_key_hex, encoder=HexEncoder)

        # Send our verification hex
        send_message(self.socket, self.verify_key_hex)
        return True

    def setup_secure_channel(self):
        # Generate our private / public key pair
        private_key, public_key = generate_keys()
        public_key = public_key.encode(encoder=HexEncoder)
        print('Server: Keys generated.')

        # Receive the client's public key
        client_public_key = receive_message(self.socket)
        client_public_key = self._verify_sender(client_public_key)
        if not client_public_key:
            return False
        client_public_key = PublicKey(client_public_key, encoder=HexEncoder)
        print('Server: Client public key received.')

        # Send our public key to the client
        send_message(self.socket, self._sign_data(public_key))
        print('Server: Public key sent.')

        # Create a secret key and send it to the client
        box = Box(private_key, client_public_key)
        secret_key = random(SecretBox.KEY_SIZE)
        encrypted = box.encrypt(secret_key)
        send_message(self.socket, self._sign_data(encrypted))
        print('Server: Secret key sent.')

        # Setup symmetric encryption using the secret key
        self._set_secret_key(secret_key)
        return True

    def send_file(self, file_id):
        file = next((file for file in self.files if file.file_id == file_id), None)
        if not file:
            return False

        hash_structure = self.merkle_tree.get_structure_with_file(file, True)

        file_json = file_to_json(file)
        self.send_bytes(bytes(file_json, encoding='utf-8'))
        structure_json = node_to_json(hash_structure)
        self.send_bytes(bytes(structure_json, encoding='utf-8'))
        return True

    def receive_file(self):
        file_json = self.receive_bytes()
        if not file_json:
            return False

        file = file_from_json(file_json.decode('utf-8'))
        self.merkle_tree.add_file(file)
        self.files.append(file)

        print('Server: Received ', file.__dict__)

        hash_structure = self.merkle_tree.get_structure_with_file(file, True)
        structure_json = node_to_json(hash_structure)
        self.send_bytes(bytes(structure_json, encoding='utf-8'))
        return True

    def get_host(self):
        return self.address, self.port
