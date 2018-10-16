from network.client import Client
from network.server import Server
from utils.file import generate_certificate


def setup_certificates():
    generate_certificate('server_cert.txt', 'SuperSecretThingThatCantBeGuessed')
    generate_certificate('client_cert.txt', 'TjahoTjahojDetHärÄrJuSkoj')


if __name__ == '__main__':
    setup_certificates()

    server = Server()
    server.start()
    client = Client()
    client.start()
