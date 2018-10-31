from network.client import Client
from network.server import Server
from utils.file import generate_certificate


def setup_certificates():
    generate_certificate('server_secret.txt', 'SuperSecretThingThatCantBeGuessed')
    generate_certificate('client_secret.txt', 'TjahoTjahojDetHärÄrJuSkoj')


if __name__ == '__main__':
    server = Server(False)
    server.start()
    client = Client(False)
    client.start()
    client.disconnect()
