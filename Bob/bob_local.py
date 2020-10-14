"""" Server (localhost) """
import socket, pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

# Key generation
bob_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())

# Assuming that Alice has bob's PK, thus saving it as PEM format to Alice's PC.
bob_key_pem = bob_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

with open("../Alice/PK_bob.pem", "wb") as key:
    key.write(bob_key_pem)


def retrieve_alice_pk():
    with open("PK_alice.pem", "rb") as pem_file:
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


def decrypt_message(msg):
    d_cipher = bob_private_key.decrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return d_cipher


def sign_message(msg):
    signature = bob_private_key.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256())
    return signature


def verify_message(msg, signature, PK):
    try:
        PK.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), hashes.SHA256())
        print("[MESSAGE VERIFIED]")

    except InvalidSignature:
        print("[WARNING INVALID SIGNATURE!!!]")


# TCP socket with ipv4
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"; port = 6677
address = (host, port)
server.bind(address)

# Handle connections
server.listen(2048)
running = True
print(f"[Server started at {host} on port {port}]")

# Creating the message to send
message = b'I once coded some Java. But it was an Island in Indonesia'

while running:
    # Accept connection from client
    client_socket, address = server.accept()
    print(f"Connection from {address} has been established...")

    # Get prerequisites
    PK_alice = retrieve_alice_pk()

    # Send message to client
    cipher_text = encrypt_message(message,PK_alice)
    signature_bob = sign_message(message)

    # Preparing data to be send
    data = (cipher_text, signature_bob)
    data_string = pickle.dumps(data)

    client_socket.send(data_string)

    # Receive message from client
    received_data = pickle.loads(client_socket.recv(2048))
    decrypted_client_message = decrypt_message(received_data[0])
    verify_message(decrypted_client_message, received_data[1], PK_alice)
    print(f"<Bob> decrypted the message '{decrypted_client_message.decode('utf-8')}'")
    running = False

    client_socket.close()


