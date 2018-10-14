import struct
import nacl.signing
import nacl.encoding
import nacl.secret
from nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey


def pack_data(data):
    # Length first in network byte order.
    return struct.pack('>I', len(data)) + data


def receive_bytes(socket, n):
    data = b''
    while len(data) < n:
        packet = socket.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


def send_message(socket, data):
    socket.sendall(pack_data(data))


def receive_message(socket):
    data_length = receive_bytes(socket, 4)
    if not data_length:
        return
    data_length = struct.unpack('>I', data_length)[0]
    data = receive_bytes(socket, data_length)
    return data


def generate_keys():
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key


def generate_signing_keys():
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
    return signing_key, verify_key, verify_key_hex


class ConnectionManager(object):
    socket = None
    _secret_box = None
    _connection_verify_key = None

    def __init__(self):
        self.signing_key, self.verify_key, self.verify_key_hex = generate_signing_keys()

    def _set_secret_key(self, key):
        self._secret_box = nacl.secret.SecretBox(key)

    def send_bytes(self, bytes):
        encrypted = self._encrypt_data(bytes)
        if not encrypted:
            return
        signed = self._sign_data(encrypted)
        send_message(self.socket, signed)

    def receive_bytes(self):
        data = receive_message(self.socket)
        if not data:
            return None

        encrypted = self._verify_sender(data)
        if not encrypted:
            return None
        decrypted = self._decrypt_data(encrypted)
        return decrypted

    def _sign_data(self, data):
        signed = self.signing_key.sign(data)
        return signed

    def _verify_sender(self, data):
        try:
            return self._connection_verify_key.verify(data)
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
