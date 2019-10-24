# -*- coding: utf-8 -*-
#!/usr/bin/env python
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key.pem', 'wb') as f:
        f.write(pem)

    return private_key

def generate_public_key():
    private_key = generate_private_key()
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key.pem', 'wb') as f:
        f.write(pem)
    return public_key, private_key

def encrypting(public_key,msg):
    encrypted = public_key.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypting(private_key,encrypted):
    original_message = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return original_message

def main():
    public_key, private_key = generate_public_key()
    print("Encriptación de mensaje")
    print("private_key:")
    print(private_key)
    print("public_key:")
    print(public_key)
    print("Encrypting")
    msg_encrip = encrypting(public_key,"Hola, este mensaje será encriptado")
    print(msg_encrip)
    print("Decrypting")
    message = decrypting(private_key,msg_encrip)
    print(message)

if __name__== "__main__":
    main()
