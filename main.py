from multiprocessing import Process

from client import Client
from server import Server

server = Server()
client = Client()


def setup_server():
    server.accept_connection()


def setup_client():
    client.connect_to_host(*server.get_host())


def server_secure_channel():
    server.setup_secure_channel()


def client_secure_channel():
    client.setup_secure_channel()


if __name__ == '__main__':
    p1 = Process(target=setup_server)
    p1.start()
    p2 = Process(target=setup_client)
    p2.start()

    p1.join()
    p2.join()

    p1 = Process(target=server_secure_channel)
    p1.start()
    p2 = Process(target=client_secure_channel)
    p2.start()

    p1.join()
    p2.join()

    print('Main complete.')
