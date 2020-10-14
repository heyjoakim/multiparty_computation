""" RSA key pair """
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# ALice key pair generation
alice_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())

alice_key_pem = alice_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

with open("PK_alice.pem", "wb") as pem:
    pem.write(alice_key_pem)

# Bob key pair generation
bob_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())
PK_bob = bob_private_key.public_key()

message = "A very secret message"
message_bytes = bytes(message, encoding="utf-8")

# ENCRYPTION
cipher_text = PK_bob.encrypt(
    message_bytes,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(),
                 label=None))

# SIGNING
signature = alice_private_key.sign(
    message_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())

data = (cipher_text, signature)

# Receiving PK_alice
with open("PK_alice.pem", "rb") as key_file:
    PK_alice = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend())

# Verifying
try:
    PK_alice.verify(
        signature,
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256())

except InvalidSignature:
    print("[WARNING INVALID SIGNATURE!!!]")

# DECRYPTION
decrypted_cipher = bob_private_key.decrypt(
    cipher_text,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

print(decrypted_cipher == message_bytes)