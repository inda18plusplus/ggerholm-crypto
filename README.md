# Secure Client - Server Communication

A simple client - server setup focused on secure communication.<br>
Using Python 3.6.

### Key Features
 - Send / receive files using both the client and the server.
 - File verification using Merkle-trees.
 - The server is limited to one client. (It's a feature)
 - The client and server secret files have to be contained within each distribution. (Also a feature)

### Algorithms Used
 - SHA256 for all hashes.
 - Ed25519 for signatures.
 - Salsa20 for encryption along with Poly1305 MAC for authentication.
 - Curve25519 for the initial public / private keys used while securing communication.

### Running
 1. Download / clone the repository.
 1. Create a virtualenv and activate it.
 1. Install the *requirements.txt* packages.
 1. Run *main.py* to start all required services or *server.py* and then *client.py* in different terminals to keep it clean.

### Commands
Syntax | Example
------ | -------
__send__ *file_id* *text* | __send__ 4 Hello World!
__get__ *file_id* | __get__ 4
__exit__ | __exit__
