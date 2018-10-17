# Secure Client - Server File Storage

A simple client - server setup focused on secure communication.

### Key Features
 - Send / receive files using both the client and the server.
 - File verification using Merkle-trees.
 - The server is limited to one client. (It's a feature)
 - The client and server certification files have to be contained within each distribution. (Also a feature)

### Algorithms Used
 - SHA256 for all hashes.
 - Ed25519 for signatures.
 - Salsa20 for encryption along with Poly1305 MAC for authentication.
 - Curve25519 for the initial public / private keys used while securing communication.