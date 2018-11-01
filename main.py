from network.client import run_client
from network.server import run_server
from utils.file import generate_certificate


def create_secrets():
    generate_certificate('server_secret.txt', 'SuperSecretThingThatCantBeGuessed')
    generate_certificate('client_secret.txt', 'TjahoTjahojDetHärÄrJuSkoj')


if __name__ == '__main__':
    run_server(False)
    run_client(False)
