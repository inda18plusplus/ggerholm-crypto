import time

from nacl.encoding import HexEncoder

from client import run_client
from server import run_server
from utils.crypto import generate_keys, generate_signing_keys


def create_secrets(name_prefix):
    private, public = generate_keys()
    (signing_key, verification_key_hex) = generate_signing_keys()

    with open('secrets/encryption/' + name_prefix + '_private.key', 'w', encoding='utf-8') as f:
        f.write(private.encode(encoder=HexEncoder).decode('utf-8').replace("'", ''))
    with open('secrets/encryption/' + name_prefix + '_public.key', 'w', encoding='utf-8') as f:
        f.write(public.encode(encoder=HexEncoder).decode('utf-8').replace("'", ''))
    with open('secrets/verification/' + name_prefix + '_sign.key', 'w', encoding='utf-8') as f:
        f.write(signing_key.encode(encoder=HexEncoder).decode('utf-8').replace("'", ''))
    with open('secrets/verification/' + name_prefix + '_verify.key', 'w', encoding='utf-8') as f:
        f.write(verification_key_hex.decode('utf-8').replace("'", ''))


if __name__ == '__main__':
    run_server(False)
    time.sleep(0.1)
    run_client(False)
