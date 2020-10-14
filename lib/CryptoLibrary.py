from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


class CryptoLibrary:

    def encrypt_message(msg, PK):
        cipher = PK.encrypt(
            msg,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None))
        return cipher

    def decrypt_message(msg, private_key):
        d_cipher = private_key.decrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        return d_cipher

    def sign_message(msg, private_key):
        signature = private_key.sign(
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