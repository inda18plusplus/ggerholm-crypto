import socket
import ssl
from threading import Thread
from typing import List

from nacl.encoding import HexEncoder
from nacl.public import Box, PublicKey, PrivateKey
from nacl.secret import SecretBox
from nacl.signing import VerifyKey, SigningKey
from nacl.utils import random

from network.request import request_from_json
from network.socket_protocol import send_message, ConnectionManager
from utils.crypto import sign
from utils.file import file_from_json, file_to_json, read_verification_key, read_encryption_key, File
from utils.merkle import MerkleTree, node_to_json


def run_server(default_ssl_impl=True):
    server = Server(default_ssl_impl)
    server.start()


class Server(ConnectionManager):
    files: List['File'] = []
    keep_alive = True

    def __init__(self, use_default_ssl=False, ip_address='127.0.0.1', port=12317):
        super().__init__(use_default_ssl)
        self.address = ip_address
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.address, self.port))

        self.merkle_tree = MerkleTree()
        self.merkle_tree.build()
        self.files = list([None for _ in range(0, 16)])

        self._signing_key = SigningKey(read_verification_key('server', 'sign'), encoder=HexEncoder)
        self._connection_verify_key = VerifyKey(read_verification_key('client', 'verify'), encoder=HexEncoder)

    def start(self):
        thread = Thread(target=self.run_thread)
        thread.start()

    def run_thread(self):
        self.connected = self.accept_connection()
        if not self.connected:
            return
        self.setup_secure_channel()

        while self.connected:
            result = self.await_request()
            if result:
                print('Server: Request processed.')
            elif self.connected:
                self.send_bytes_secure(bytes('error', encoding='utf-8'))
                print('Server: Request could not be processed.')
        if self.keep_alive:
            self.run_thread()

    def accept_connection(self):
        self.server_socket.listen(5)
        self.socket, address = self.server_socket.accept()
        print('Server: Client connected from', address)

        if not self.default_ssl:
            return True

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations('secrets/ssl/client.pem')
        context.load_cert_chain(certfile='secrets/ssl/server.pem', keyfile='secrets/ssl/server.key')

        self.socket = context.wrap_socket(self.socket, server_side=True)
        cert = self.socket.getpeercert()
        if not cert or ('commonName', 'Saturn') not in cert['subject'][5]:
            self.disconnect()
            return False

        return True

    def setup_secure_channel(self):
        if not self.connected or self.default_ssl:
            return False

        private_key = PrivateKey(read_encryption_key('server', 'private'), encoder=HexEncoder)
        client_public_key = PublicKey(read_encryption_key('client', 'public'), encoder=HexEncoder)
        print('Server: Keys loaded.')

        # Create a secret key and send it to the client
        box = Box(private_key, client_public_key)
        secret_key = random(SecretBox.KEY_SIZE)
        encrypted = box.encrypt(secret_key)
        send_message(self.socket, sign(self._signing_key, encrypted))
        print('Server: Secret key sent.')

        # Setup symmetric encryption using the secret key
        self._set_secret_key(secret_key)
        return True

    def await_request(self):
        if not self.connected:
            return False

        request_json = self.receive_bytes_secure()
        if not request_json:
            return False
        request = request_from_json(request_json.decode('utf-8'))
        if not request:
            return False

        if request.type == 'get_file':
            file_id = int(request.data)
            return self.send_file(file_id)
        if request.type == 'send_file':
            file = file_from_json(request.data)
            return self.receive_file(file)
        if request.type == 'exit':
            self.keep_alive = False
            self.disconnect()
            return True
        return True

    def send_file(self, file_id):
        if not self.connected:
            return False

        try:
            file = self.files[file_id]
            if not file:
                return False
        except IndexError:
            return False

        hash_structure = self.merkle_tree.get_structure_with_file(file, True)

        file_json = file_to_json(file)
        self.send_bytes_secure(bytes(file_json, encoding='utf-8'))
        structure_json = node_to_json(hash_structure)
        self.send_bytes_secure(bytes(structure_json, encoding='utf-8'))
        return True

    def receive_file(self, file):
        if not self.connected:
            return False
        if not self.merkle_tree.insert_file(file):
            return False
        self.files[file.file_id] = file

        print('Server: Received ', file.__dict__)

        hash_structure = self.merkle_tree.get_structure_with_file(file, True)
        structure_json = node_to_json(hash_structure)
        self.send_bytes_secure(bytes(structure_json, encoding='utf-8'))
        return True

    def get_host(self):
        return self.address, self.port


if __name__ == '__main__':
    run_server()
