import nacl.signing
import nacl.encoding
import nacl.secret
import nacl.utils
import socket
from nacl.exceptions import BadSignatureError
from nacl.public import Box

from file import File
from merkle import MerkleTree
from socket_protocol import receive_message, generate_keys, generate_signing_keys, send_message


class Server(object):
    files = []
    _secret_box = None
    _client_verify_key = None
    _client_socket = None

    def __init__(self):
        self.address = '127.0.0.1'
        self.port = 12317
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.address, self.port))

        self.signing_key, self.verify_key, self.verify_key_hex = generate_signing_keys()

        self.merkle_tree = MerkleTree(16)

    def accept_connection(self):
        self.server_socket.listen(5)
        self._client_socket, address = self.server_socket.accept()
        print('Server: Client connected from', address)

        # Receive the client's verification hex
        client_key_hex = receive_message(self._client_socket)
        if not client_key_hex:
            return
        self._client_verify_key = nacl.signing.VerifyKey(client_key_hex, encoder=nacl.encoding.HexEncoder)

        # Send our verification hex
        send_message(self._client_socket, self.verify_key_hex)

    def setup_secure_channel(self):
        # Generate our private / public key pair
        private_key, public_key = generate_keys()
        public_key = public_key.encode(encoder=nacl.encoding.HexEncoder)
        print('Server: Keys generated.')

        # Receive the client's public key
        client_public_key = receive_message(self._client_socket)
        client_public_key = self._verify_sender(client_public_key)
        if not client_public_key:
            return
        client_public_key = nacl.public.PublicKey(client_public_key, encoder=nacl.encoding.HexEncoder)
        print('Server: Client public key received.')

        # Send our public key to the client
        send_message(self._client_socket, self._sign_data(public_key))
        print('Server: Public key sent.')

        # Create a secret key and send it to the client
        box = Box(private_key, client_public_key)
        secret_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        encrypted = box.encrypt(secret_key)
        send_message(self._client_socket, self._sign_data(encrypted))
        print('Server: Secret key sent.')

        # Setup symmetric encryption using the secret key
        self._secret_box = nacl.secret.SecretBox(secret_key)

    def send_file(self, file_id):
        file_data = next((file.data for file in self.files if file.file_id == file_id), default=None)
        if not file_data:
            return

        hashes = self.merkle_tree.foundation
        hashes[file_id] = None

        encrypted_data = self._encrypt_data(file_data)
        if not encrypted_data:
            return
        signed_data = self._sign_data(encrypted_data)
        send_message(self._client_socket, signed_data)
        # TODO: Send hashes

    def receive_file(self):
        data = receive_message(self._client_socket)
        if not data:
            return

        file = self._verify_sender(data)
        if not file:
            return
        plaintext = self._decrypt_data(file)
        if not plaintext:
            return

        file = File(plaintext.file_id, plaintext.data)
        self.merkle_tree.add_file(file)
        self.files.append(file)

    def _sign_data(self, data):
        signed = self.signing_key.sign(data)
        return signed

    def _verify_sender(self, data):
        try:
            return self._client_verify_key.verify(data)
        except BadSignatureError:
            return None

    def _encrypt_data(self, data):
        encrypted = self._secret_box.encrypt(data)
        if len(encrypted) != len(data) + self._secret_box.NONCE_SIZE + self._secret_box.MACBYTES:
            return None
        return encrypted

    def _decrypt_data(self, data):
        plaintext = self._secret_box.decrypt(data)
        return plaintext

    def get_host(self):
        return self.address, self.port


server = Server()
server.accept_connection()
server.setup_secure_channel()
