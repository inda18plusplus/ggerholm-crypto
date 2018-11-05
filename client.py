import socket
import ssl

from nacl.encoding import HexEncoder
from nacl.public import Box, PublicKey, PrivateKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random

from network.request import Request, request_to_json
from network.socket_protocol import receive_message, ConnectionManager
from utils.crypto import verify_sender
from utils.file import File, file_from_json, file_to_json, read_encryption_key, read_verification_key
from utils.merkle import get_root_hash


def run_client(default_ssl_impl=True):
    client = Client(default_ssl_impl)
    client.start()

    secret_box = SecretBox(random(SecretBox.KEY_SIZE))
    print('Ready to serve:')
    while client.connected:
        cmd = input('> ')
        tokens = cmd.split(' ')
        try:
            if len(cmd) == 0 or tokens[0] == 'exit':
                client.exit()
            elif tokens[0] == 'send':
                fid = int(tokens[1])
                data = str(' '.join(tokens[2:]))
                if len(data) == 0:
                    print('No data provided.')
                    continue
                encrypted_data = secret_box.encrypt(bytes(data, encoding='utf-8'), encoder=HexEncoder)
                client.send_file(File(fid, encrypted_data.decode('utf-8')))
            elif tokens[0] == 'get':
                fid = int(tokens[1])
                result = client.request_file(fid)
                if result and result.file_id != fid:
                    print('Incorrect file received.')
                elif result:
                    decrypted = secret_box.decrypt(bytes(result.data, encoding='utf-8'), encoder=HexEncoder)
                    print(decrypted.decode('utf-8'))
                else:
                    print('No data received.')
            else:
                print('Command not recognized.')
        except ValueError:
            print('Incorrect argument type.')
        except IndexError:
            print('Incorrect number of arguments.')
    print('Disconnected')


class Client(ConnectionManager):
    _latest_top_hash = None

    def __init__(self, use_default_ssl=False):
        super().__init__(use_default_ssl)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self._signing_key = SigningKey(read_verification_key('client', 'sign'), encoder=HexEncoder)
        self._connection_verify_key = VerifyKey(read_verification_key('server', 'verify'), encoder=HexEncoder)

    def start(self, host_ip='localhost', port=12317):
        self.connected = self.connect_to_host(host_ip, port)
        if not self.connected:
            return
        self.setup_secure_channel()

    def connect_to_host(self, host, port):
        self.socket.connect((host, port))
        print('Client: Server connection established.')

        if not self.default_ssl:
            return True

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations('secrets/ssl/server.pem')
        context.load_cert_chain(certfile='secrets/ssl/client.pem', keyfile='secrets/ssl/client.key')

        if ssl.HAS_SNI:
            self.socket = context.wrap_socket(self.socket, server_side=False, server_hostname=host)
        else:
            self.socket = context.wrap_socket(self.socket, server_side=False)

        cert = self.socket.getpeercert()
        if not cert or ('commonName', 'Jupiter') not in cert['subject'][5]:
            self.disconnect()
            return False

        return True

    def setup_secure_channel(self):
        if not self.connected or self.default_ssl:
            return False

        private_key = PrivateKey(read_encryption_key('client', 'private'), encoder=HexEncoder)
        server_public_key = PublicKey(read_encryption_key('server', 'public'), encoder=HexEncoder)
        print('Client: Keys loaded.')

        # Receive the secret key generated by the server
        box = Box(private_key, server_public_key)
        secret_key = receive_message(self.socket)
        secret_key = verify_sender(self._connection_verify_key, secret_key)
        if not secret_key:
            print('Client: Secret key not received.')
            return False
        print('Client: Secret key received.')

        # Setup symmetric encryption using the secret key
        secret_key = box.decrypt(secret_key)
        self._set_secret_key(secret_key)
        return True

    def exit(self):
        if not self.connected:
            return False
        request = Request('exit', '')
        request_json = request_to_json(request)
        self.send_bytes_secure(bytes(request_json, encoding='utf-8'))
        self.disconnect()
        return True

    def send_file(self, file):
        if not self.connected:
            return False

        request = Request('get_structure', file.file_id)
        request_json = request_to_json(request)
        self.send_bytes_secure(bytes(request_json, encoding='utf-8'))
        prev_structure = self.receive_bytes_secure()
        expected_root_hash = get_root_hash(prev_structure, file)

        file_json = file_to_json(file)
        request = Request('send_file', file_json)
        request_json = request_to_json(request)
        self.send_bytes_secure(bytes(request_json, encoding='utf-8'))

        hash_structure = self.receive_bytes_secure()
        if not hash_structure or hash_structure.decode('utf-8') == 'error':
            return False

        received_root_hash = get_root_hash(hash_structure, file)
        if received_root_hash == expected_root_hash:
            self._latest_top_hash = received_root_hash
        else:
            print('Client: Received incorrectly modified structure.')
            self.disconnect()
            return False

        print('Client: Calculated top hash:', self._latest_top_hash)
        return True

    def request_file(self, file_id):
        if not self.connected:
            return None
        request = Request('get_file', file_id)
        request_json = request_to_json(request)
        self.send_bytes_secure(bytes(request_json, encoding='utf-8'))
        return self.receive_file()

    def receive_file(self):
        if not self.connected:
            return None

        file_json = self.receive_bytes_secure()
        if not file_json or file_json.decode('utf-8') == 'error':
            return None
        file = file_from_json(file_json.decode('utf-8'))
        hash_structure = self.receive_bytes_secure()
        if not hash_structure:
            return None

        provided_root_hash = get_root_hash(hash_structure, file)
        if not self._latest_top_hash:
            self._latest_top_hash = provided_root_hash
        elif self._latest_top_hash != provided_root_hash:
            print('Merkle verification failed.')
            return None

        return file


if __name__ == '__main__':
    run_client()
