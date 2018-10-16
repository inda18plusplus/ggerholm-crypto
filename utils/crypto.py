from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.hash import sha256
from nacl.public import PrivateKey
from nacl.secret import SecretBox
from nacl.signing import VerifyKey, SigningKey


def hash_sha256(data: bytes):
    return sha256(data, encoder=HexEncoder)


def encrypt(secret_box: SecretBox, data: bytes):
    encrypted = secret_box.encrypt(data)
    if len(encrypted) != len(data) + secret_box.NONCE_SIZE + secret_box.MACBYTES:
        return None
    return encrypted


def decrypt(secret_box: SecretBox, data: bytes):
    encrypted = secret_box.decrypt(data)
    return encrypted


def sign(signing_key: SigningKey, data: bytes):
    signed = signing_key.sign(data)
    return signed


def verify_sender(verify_key: VerifyKey, data: bytes):
    try:
        return verify_key.verify(data)
    except BadSignatureError:
        return None


def generate_keys():
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key


def generate_signing_keys():
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    verify_key_hex = verify_key.encode(encoder=HexEncoder)
    return signing_key, verify_key_hex
