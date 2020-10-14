"""" Alice (localhost) """
import socket, pickle, random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

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


def decrypt_message(msg):
    d_cipher = alice_private_key.decrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return d_cipher


def sign_message(msg):
    signature = alice_private_key.sign(
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
    # Get prerequisites
    PK_bob = retrieve_bobs_pk()

    # Receive from server
    received_data = pickle.loads(server.recv(2048))
    decrypted_server_message = decrypt_message(received_data[0])
    print("<Bob> ", decrypted_server_message.decode("utf-8"))
    verify_message(decrypted_server_message, received_data[1], PK_bob)
    print(f"<Alice> decrypted the message '{decrypted_server_message.decode('utf-8')}'")

    # Send message to server
    cipher_text = encrypt_message(message, PK_bob)
    signature_alice = sign_message(message)

    # Sending message encrypted and signed
    data = (cipher_text, signature_alice)
    data_string = pickle.dumps(data)
    server.send(data_string)
    running = False

    server.close()
