""" RSA key pair """
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())
#PK_client = client_private_key.public_key()

#  Printing the PK in PEM encoded, just for visualization purposes
public_key_pem = client_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")

f = open("client_PK.pem", "a")
f.write(public_key_pem)

with open("client_PK.pem", "rb") as key_file:
    CLIENT_PK = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

test = CLIENT_PK.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")

print(test)