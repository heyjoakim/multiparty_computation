"""" Client (localhost) """
import socket

# TCP with ipv4
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"; port = 6677
address = (host, port)

server.connect(address)
full_msg = ''

message = input('> ')

while message != 'quit':
    msg = server.recv(1)
    if len(msg) <= 0:
        break
    full_msg += msg.decode("utf-8")

print(full_msg)
