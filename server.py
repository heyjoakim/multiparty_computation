"""" Server (localhost) """
import socket

# TCP socket with ipv4
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1" # faster than localhost due to no DNS lookup
port = 6677
server.bind((host,port))

# Handle connections
server.listen(2)

while True:
    clientsocket, address = server.accept() # : -> (conn,adress)
    print(f"Connection from {address} has been established.")
    clientsocket.send(bytes("Hey client", "utf-8"))
    clientsocket.close()
