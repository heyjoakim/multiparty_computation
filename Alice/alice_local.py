"""" Alice (localhost) """
import socket
import pickle
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Key generation
alice_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())

# Assuming that Bob has Alice's PK, thus saving it as PEM format at Bob's PC.
alice_key_pem = alice_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

with open("../Bob/PK_alice.pem", "wb") as key:
    key.write(alice_key_pem)


def retrieve_bobs_pk():
    with open("PK_bob.pem", "rb") as pem_file:
        PK = serialization.load_pem_public_key(
            pem_file.read(),
            backend=default_backend())
        return PK


def encrypt_message(msg, PK):
    cipher = PK.encrypt(
        msg,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))
    return cipher


def sign_message(msg):
    signature = alice_private_key.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256())
    return signature


# TCP with ipv4
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"; port = 6677
address = (host, port)

# Connect to address
server.connect(address)
running = True
print(f"[Connected to {host} at port {port}]")

# Creating the message to be send
message = b"Linux fanboys are the new gangsters"  # Encoded in bytes

while running:
    # Receive from server
    server_message = server.recv(2048)
    print("<Bob> ", server_message.decode("utf-8"))

    # Get prerequisites
    PK_bob = retrieve_bobs_pk()

    # Send message to server
    cipher_text = encrypt_message(message, PK_bob)
    signature_alice = sign_message(message)

    # Sending message encrypted and signed
    data = (cipher_text, signature_alice)
    data_string = pickle.dumps(data)
    server.send(data_string)
    running = False

server.close()
