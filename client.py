"""" Client """
import socket
host = "127.0.0.1"
port = 6677

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.connect((host, port))
msg = server.recv(1024)
print(msg.decode("utf-8"))
