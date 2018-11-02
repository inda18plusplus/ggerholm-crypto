import socket
import ssl
from threading import Thread

from nacl.encoding import HexEncoder
from nacl.public import Box, PublicKey
from nacl.secret import SecretBox
from nacl.signing import VerifyKey
from nacl.utils import random

from network.request import request_from_json
from network.socket_protocol import receive_message, send_message, ConnectionManager
from utils.crypto import generate_keys, verify_sender, sign
from utils.file import file_from_json, file_to_json, read_secret
from utils.merkle import MerkleTree, node_to_json


def run_server(default_ssl_impl=False):
    server = Server(default_ssl_impl)
    server.start()
    while not server.listening:
        pass


class Server(ConnectionManager):
    files = []
    keep_alive = True
    listening = False

    def __init__(self, use_default_ssl=False, ip_address='127.0.0.1', port=12317):
        super().__init__(use_default_ssl)
        self.address = ip_address
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.address, self.port))

        self.merkle_tree = MerkleTree()
        self.merkle_tree.build()

        self.secret = read_secret('server_secret.txt')
        self.client_secret = read_secret('client_secret.txt')

    def start(self):
        thread = Thread(target=self.run_thread)
        thread.start()

    def run_thread(self):
        self.listening = True
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

        if self.default_ssl:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations('secrets/client.pem')
            context.load_cert_chain(certfile='secrets/server.pem', keyfile='secrets/server.key')

            self.socket = context.wrap_socket(self.socket, server_side=True)
            cert = self.socket.getpeercert()
            if not cert or ('commonName', 'Saturn') not in cert['subject'][5]:
                self.disconnect()
                return False
            return True

        # Receive the client's verification hex
        client_key_hex = receive_message(self.socket)
        if not client_key_hex:
            self.socket.close()
            return False
        self._connection_verify_key = VerifyKey(client_key_hex, encoder=HexEncoder)

        # Verify that both the key and the secret/password arrived unchanged
        client_secret = receive_message(self.socket)
        client_secret = verify_sender(self._connection_verify_key, client_secret)
        if not client_secret:
            self.socket.close()
            print('Server: Client password or key tampered with.')
            return False

        client_secret = client_secret.decode('utf-8')
        if client_secret != self.client_secret:
            self.socket.close()
            print('Server: Client password invalid.')
            return False

        # Send our verification hex
        send_message(self.socket, self.verify_key_hex)
        # Send our signed certificate
        signed = sign(self._signing_key, bytes(self.secret, encoding='utf-8'))
        send_message(self.socket, signed)

        return True

    def setup_secure_channel(self):
        if not self.connected or self.default_ssl:
            return False

        # Generate our private / public key pair
        private_key, public_key = generate_keys()
        public_key = public_key.encode(encoder=HexEncoder)
        print('Server: Keys generated.')

        # Receive the client's public key
        client_public_key = receive_message(self.socket)
        client_public_key = verify_sender(self._connection_verify_key, client_public_key)
        if not client_public_key:
            return False
        client_public_key = PublicKey(client_public_key, encoder=HexEncoder)
        print('Server: Client public key received.')

        # Send our public key to the client
        send_message(self.socket, sign(self._signing_key, public_key))
        print('Server: Public key sent.')

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

        file = next((file for file in self.files if file.file_id == file_id), None)
        if not file:
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
        prev_entry = next((f for f in self.files if f.file_id == file.file_id), None)
        if prev_entry:
            prev_entry.data = file.data
        else:
            self.files.append(file)

        print('Server: Received ', file.__dict__)

        hash_structure = self.merkle_tree.get_structure_with_file(file, True)
        structure_json = node_to_json(hash_structure)
        self.send_bytes_secure(bytes(structure_json, encoding='utf-8'))
        return True

    def get_host(self):
        return self.address, self.port


if __name__ == '__main__':
    run_server()
