"""" Alice (localhost) """
import socket, pickle, random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, asymmetric
from lib.MyCryptoLibrary import MyCryptoLibrary


# Key generation
alice_private_key = asymmetric.rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())

# Assuming that Bob has Alice's PK, thus saving it as PEM format at Bob's PC.
alice_key_pem = alice_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

with open("PK_alice.pem", "wb") as key:
    key.write(alice_key_pem)


def retrieve_bobs_pk():
    with open("PK_bob.pem", "rb") as pem_file:
        PK = serialization.load_pem_public_key(
            pem_file.read(),
            backend=default_backend())
        return PK


def decrypt_and_verify(data, PK):
    decrypted_message = MyCryptoLibrary.decrypt_message(data[0], alice_private_key)
    MyCryptoLibrary.verify_message(decrypted_message, data[1], PK)
    print(f"<Alice> decrypted the message '{decrypted_message.decode('utf-8')}'")
    return decrypted_message


def send_encrypted_signed_message(msg, PK):
    cipher_text = MyCryptoLibrary.encrypt_message(msg, PK)
    signature_alice = MyCryptoLibrary.sign_message(msg, alice_private_key)
    data = (cipher_text, signature_alice)
    data_string = pickle.dumps(data)
    server.send(data_string)


# TCP with ipv4
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"; port = 6677
address = (host, port)

# Connect to address
server.connect(address)
running = True
print(f"[Connected to {host} at port {port}]")


while running:
    # Get prerequisites
    PK_bob = retrieve_bobs_pk()

    # [1] message received
    received_data = pickle.loads(server.recv(2048))
    decrypt_and_verify(received_data, PK_bob)

    # [2] Send message Com(a,r) to Bob
    a = '009'  # Alice not honest!!!!!!!!!!!!!!!!
    r = '01000100101101000010111001110111101010111111001011111'
    c = bytes(a + r, encoding="utf-8")
    c_hashed = MyCryptoLibrary.hash_message(c)
    send_encrypted_signed_message(c_hashed, PK_bob)

    # [3] message Com(a,r) received from Bob
    received_data2 = pickle.loads((server.recv(2048)))
    decrypt_and_verify(received_data2, PK_bob)

    # [4] send second message (a,r) to Bob
    a_r = bytes(a + "," + r, encoding="utf-8")
    send_encrypted_signed_message(a_r, PK_bob)

    # [5] second message (a,r) received from Bob

    running = False
    server.close()
