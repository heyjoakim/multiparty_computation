"""" Server (localhost) """
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Key generation
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())
PK_server = server_private_key.public_key()




# TCP socket with ipv4
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"; port = 6677
address = (host, port)
server.bind(address)

# Handle connections
server.listen(10)
print(f"[Server started at {host} on port {port}]")

while exec:
    # Accept connection from client
    client_socket, address = server.accept()
    print(f"Connection from {address} has been established...")

    # Send message to client
    client_socket.send(bytes("Hey client this is my PK", "utf-8"))
    client_socket.send(bytes(str(PK_server), "utf-8"))

    # Receive message from client
    client_message = client_socket.recv(1024).decode('utf-8')
    print("<Client> ", client_message)
    exec = False

client_socket.close()


