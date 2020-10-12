"""" Server (localhost) """
import socket

# TCP socket with ipv4
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"; port = 6677
address = (host, port)
server.bind(address)

# Handle connections
server.listen(10)
print("[Server started]", "at", host, "on port", port)

while True:
    client_socket, address = server.accept()
    print(f"Connection from {address} has been established.")
    client_socket.send(bytes("Hey client", "utf-8"))
    client_socket.close()


