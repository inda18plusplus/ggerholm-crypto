# Secure Client - Server Communication

A simple client - server setup focused on secure communication.<br>
Using Python 3.6. Only tested on Windows 10.

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
 - Download / clone the repository.
 - Create a virtualenv.
 - Install the *requirements.txt* packages.
 - Activate the virtualenv and run *main.py* or *server.py* and then *client.py* in different terminals to keep it clean.

### Commands
 - send *file_id* *text* (e.g. 'send 4 Hello World!')
 - get *file_id*
 - exit