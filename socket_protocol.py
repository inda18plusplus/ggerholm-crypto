import struct

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey


def pack_data(data):
    # Length first in network byte order.
    return struct.pack('>I', len(data)) + data


def receive_bytes(socket, length):
    data = b''
    while len(data) < length:
        packet = socket.recv(length - len(data))
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
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    verify_key_hex = verify_key.encode(encoder=HexEncoder)
    return signing_key, verify_key, verify_key_hex


class ConnectionManager(object):
    socket = None
    _secret_box = None
    _connection_verify_key = None

    def __init__(self):
        self.signing_key, self.verify_key, self.verify_key_hex = generate_signing_keys()

    def _set_secret_key(self, key):
        self._secret_box = SecretBox(key)

    def send_bytes(self, data: bytes):
        """
        Encrypts and signs the provided data then sends it to the connected device.
        :param data: The data (as a bytes-object) to be sent.
        :return: True if the data was successfully encrypted and sent, otherwise False.
        """
        encrypted = self._encrypt_data(data)
        if not encrypted:
            return False
        signed = self._sign_data(encrypted)
        send_message(self.socket, signed)
        return True

    def receive_bytes(self):
        """
        Waits for data to be read then decrypts it and verifies the sender.
        :return: The decrypted data or None if the decryption or verification failed, or no data was received.
        """
        data = receive_message(self.socket)
        if not data:
            return None

        encrypted = self._verify_sender(data)
        if not encrypted:
            return None
        decrypted = self._decrypt_data(encrypted)
        return decrypted

    def _sign_data(self, data: bytes):
        signed = self.signing_key.sign(data)
        return signed

    def _verify_sender(self, data: bytes):
        try:
            return self._connection_verify_key.verify(data)
        except BadSignatureError:
            return None

    def _encrypt_data(self, data: bytes):
        encrypted = self._secret_box.encrypt(data)
        if len(encrypted) != len(data) + self._secret_box.NONCE_SIZE + self._secret_box.MACBYTES:
            return None
        return encrypted

    def _decrypt_data(self, data: bytes):
        decrypted = self._secret_box.decrypt(data)
        return decrypted
