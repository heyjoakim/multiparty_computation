"""" Server (localhost) """
import socket, pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, asymmetric
from lib.MyCryptoLibrary import MyCryptoLibrary

# Key generation
bob_private_key = asymmetric.rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())

# Assuming that Alice has bob's PK, thus saving it as PEM format to Alice's PC.
bob_key_pem = bob_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

with open("PK_bob.pem", "wb") as key:
    key.write(bob_key_pem)


def retrieve_alice_pk():
    with open("PK_alice.pem", "rb") as pem_file:
        PK = serialization.load_pem_public_key(
            pem_file.read(),
            backend=default_backend())
        return PK


def decrypt_and_verify(data, PK):
    decrypted_message = MyCryptoLibrary.decrypt_message(data[0], bob_private_key)
    MyCryptoLibrary.verify_message(decrypted_message, data[1], PK)
    #print(f"<Bob> decrypted the message '{decrypted_message}'")
    if type(decrypted_message) is tuple:
        test = pickle.loads(decrypted_message)
        print(test)
        return test
    else:
        return decrypted_message


def send_encrypted_signed_message(msg, PK):
    cipher_text = MyCryptoLibrary.encrypt_message(msg, PK)
    signature_alice = MyCryptoLibrary.sign_message(msg, bob_private_key)
    data = (cipher_text, signature_alice)
    data_string = pickle.dumps(data)
    client_socket.send(data_string)


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

while running:
    # Accept connection from client
    client_socket, address = server.accept()
    print(f"Connection from {address} has been established...")

    # Get prerequisites
    PK_alice = retrieve_alice_pk()

    # Send message to client
    message = b'I once coded some Java. But it was an Island in Indonesia'
    send_encrypted_signed_message(message, PK_alice)

    # Receive message from client
    received_data = pickle.loads(client_socket.recv(2048))
    decrypted_hashed_c_from_alice = decrypt_and_verify(received_data, PK_alice)

    # Message 2
    message2 = b' Hi i am message2 from Bob'
    send_encrypted_signed_message(message, PK_alice)

    # Receive second message (a,r) from Alice
    received_data2 = pickle.loads((client_socket.recv(2048)))
    decrypted_a_r = decrypt_and_verify(received_data2, PK_alice)
    decoded_split_a_r = decrypted_a_r.decode("utf-8").split(",")
    opened_commitment = bytes(decoded_split_a_r[0] + decoded_split_a_r[1], "utf-8")

    # Hashing a + r for checking
    opened_commitment_hashed = MyCryptoLibrary.hash_message(opened_commitment)

    if decrypted_hashed_c_from_alice == opened_commitment_hashed:
        print("[Success] No changes we made to the message")
        alice_a = decoded_split_a_r[0]
        print("Alice's a was: ", alice_a)
    else:
        print("[WARNING] Alice changed her message")

    running = False
    client_socket.close()


