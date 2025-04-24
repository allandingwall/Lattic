import os
import hashlib
from kyber_py.ml_kem import ML_KEM_1024
from dilithium_py.ml_dsa import ML_DSA_87
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_dsa_keys():
    dsa_pub_key, dsa_sec_key = ML_DSA_87.keygen()
    return dsa_pub_key, dsa_sec_key

def create_signature(dsa_sec_key, msg):
    return ML_DSA_87.sign(dsa_sec_key, msg)

def verify_signature(pk, msg, sig):
    return ML_DSA_87.verify(pk, msg, sig)

def generate_kem_keys():
    print("Server generating encapsulation and decapsulation keys...")
    encap_key, decap_key = ML_KEM_1024.keygen()
    return encap_key, decap_key

def encapsulate_key(encap_key):
    key, ciphertext = ML_KEM_1024.encaps(encap_key)
    return key, ciphertext

def decapsulate_key(decap_key, ciphertext):
    return ML_KEM_1024.decaps(decap_key, ciphertext)

def derive_aes_key(salt, shared_key):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=256,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(bytes(shared_key))

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=256,
        salt=salt,
        iterations=100000,
    )

    try:
        kdf.verify(shared_key, key)
        return key
    
    except:
        raise Exception("Key derivation failed")

if __name__ == "__main__":
    # SERVER
    # Generate signing keys at certain time point
    print("Server generating signing keys...")
    dsa_pub_key, dsa_sec_key = generate_dsa_keys()
    print(f"Server Public Signing Key hash: {hashlib.sha256(dsa_pub_key).hexdigest()}")
    # SEND PUBLIC KEY TO CERTIFICATE AUTHORITY (DATABASE)

    # When client triggers session:
    encap_key, decap_key = generate_kem_keys()
    print("Server creating digital signature on encapsulation key...")
    sig = create_signature(dsa_sec_key, encap_key)
    print("Server sending signature and encapsulation key to client... ")
    ## SEND SIG, EK TO CLIENT
    print()


    # CLIENT
    ## OBTAIN PUBLIC KEY FROM CERTIFICATE AUTHORITY
    print("Client verifying signature...")
    if verify_signature(dsa_pub_key, encap_key, sig):
        print("Client generating shared PQ key...")
        client_pq_key, ciphertext = encapsulate_key(encap_key)
        print(f"Client PQ Key hash: {hashlib.sha256(client_pq_key).hexdigest()}")
    else:
        raise Exception("Signature verification failed")
    
    salt = os.urandom(16)
    print("Client deriving AES key...")
    client_aes_key = derive_aes_key(salt, client_pq_key)
    print(f"Client AES Key hash: {hashlib.sha256(client_aes_key).hexdigest()}")
    ## SEND CIPHERTEXT AND SALT BACK TO SERVER
    print()
    

    # SERVER
    print("Server generating shared PQ key...")
    server_pq_key = decapsulate_key(decap_key, ciphertext)
    print(f"Server PQ Key hash: {hashlib.sha256(server_pq_key).hexdigest()}")

    print("Server deriving AES key...")
    server_aes_key = derive_aes_key(salt, server_pq_key)   
    print(f"Server AES Key hash: {hashlib.sha256(server_aes_key).hexdigest()}")