""" RSA key pair """
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
#import hashlib

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

#print(m.digest())


# ENCRYPTION
def encrypt(msg, PK):
    cipher_text = PK.encrypt(
        msg,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))
    return cipher_text

# SIGNING
signature = alice_private_key.sign(
    message_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())

#data = (cipher_text, signature)

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
def decrypt(msg, private_key):
    decrypted_cipher = private_key.decrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return decrypted_cipher


a = '009'
r = '01000100101101000010111001110111101010111111001011111'
c_bytes = bytes(a + r, encoding="utf-8")

m = hashes.Hash(hashes.SHA256(), backend=default_backend())
m.update(c_bytes)
c_hashed = m.finalize()

c_hashed_encrypted = encrypt(c_hashed, PK_bob)

a2 = a
r2 = r
ar_bytes = bytes(a2 + r2, encoding="utf-8")

c_hashed_decrypted = decrypt(c_hashed_encrypted, bob_private_key)

H = hashes.Hash(hashes.SHA256(), backend=default_backend())
H.update(ar_bytes)
H_hashed = H.finalize()

bob_a = '001'

if H_hashed == c_hashed_decrypted:
    print("[Success] No changes we made to the message")
    dice_throw_alice = bin(int(a)^int(bob_a))
    dice_throw_bob = bin(int(bob_a)^int(a))
    print("bob", dice_throw_bob)
    print("alice", dice_throw_alice)


    # Convert the binary strings back to integers
    converted_dice_throw_alice = (int(dice_throw_alice, 2) % 6) + 1
    converted_dice_throw_bob = (int(dice_throw_bob, 2) % 6) + 1
    print(converted_dice_throw_alice)
    print(converted_dice_throw_bob)
else:
    print("[WARNING] Alice changed her message")
