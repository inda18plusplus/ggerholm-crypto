import struct

from nacl.secret import SecretBox

from utils.crypto import decrypt, verify_sender, sign, encrypt, generate_signing_keys


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


class ConnectionManager(object):
    connected = False
    socket = None
    _secret_box = None
    _connection_verify_key = None

    def __init__(self, use_default_ssl=False):
        self._signing_key, self.verify_key_hex = generate_signing_keys()
        self.default_ssl = use_default_ssl

    def _set_secret_key(self, key):
        self._secret_box = SecretBox(key)

    def send_bytes(self, data: bytes):
        """
        Encrypts and signs the provided data then sends it to the connected device.
        :param data: The data (as a bytes-object) to be sent.
        :return: True if the data was successfully encrypted and sent, otherwise False.
        """
        if not self.connected:
            return False

        if self.default_ssl:
            send_message(self.socket, data)
            return True

        encrypted = encrypt(self._secret_box, data)
        if not encrypted:
            return False
        signed = sign(self._signing_key, encrypted)
        send_message(self.socket, signed)
        return True

    def receive_bytes(self):
        """
        Waits for data to be read then decrypts it and verifies the sender.
        :return: The decrypted data or None if the decryption or verification failed, or no data was received.
        """
        if not self.connected:
            return None

        data = receive_message(self.socket)
        if not data:
            return None

        if self.default_ssl:
            return data

        encrypted = verify_sender(self._connection_verify_key, data)
        if not encrypted:
            return None
        decrypted = decrypt(self._secret_box, encrypted)
        return decrypted

    def disconnect(self):
        if not self.connected:
            return

        self.socket.shutdown()
        self.socket.close()
        self.connected = False
