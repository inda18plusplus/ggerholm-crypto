import struct
import nacl.signing
import nacl.encoding
from nacl.public import PrivateKey


def pack_data(data):
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
