from network.client import run_client
from network.server import run_server


def create_secrets():
    with open('secrets/server_secret.txt', 'w', encoding='utf-8') as f:
        f.write('SuperSecretThingThatCantBeGuessed')
    with open('secrets/client_secret.txt', 'w', encoding='utf-8') as f:
        f.write('TjahoTjahojDetHärÄrJuSkoj')


if __name__ == '__main__':
    run_server(False)
    run_client(False)
