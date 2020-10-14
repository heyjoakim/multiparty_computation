"""" Client (localhost) """
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# TCP with ipv4
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"; port = 6677
address = (host, port)

# Connect to address
server.connect(address)
running = True
print(f"[Connected to {host} at port {port}]")


while running:
    # Receive from server
    server_message = server.recv(1024)
    print("<Server> ", server_message.decode("utf-8"))

    # Send message to server
    server.send(bytes("hi server", "utf-8"))

    running = False
    server.close()
