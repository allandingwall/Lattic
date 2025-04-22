import os
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
    dsa_pub_key, dsa_sec_key = generate_dsa_keys()
    # SEND PUBLIC KEY TO CERTIFICATE AUTHORITY
    
    # When client triggers session:
    encap_key, decap_key = generate_kem_keys()
    sig = create_signature(dsa_sec_key, encap_key)
    ## SEND SIG, EK TO CLIENT


    # CLIENT
    ## OBTAIN PK FROM CERTIFICATE AUTHORITY
    if verify_signature(dsa_pub_key, encap_key, sig):
        client_pq_key, ciphertext = encapsulate_key(encap_key)
    else:
        raise Exception("Signature verification failed")
    
    salt = os.urandom(16)
    client_aes_key = derive_aes_key(salt, client_pq_key)
        ## SEND CIPHERTEXT AND SALT BACK TO SERVER
    

    # SERVER
    server_pq_key = decapsulate_key(decap_key, ciphertext)
    server_aes_key = derive_aes_key(salt, server_pq_key)



    print(f"Client PQ Key: {client_pq_key.hex()}")
    print(f"Server PQ Key: {server_pq_key.hex()}")
    print(f"Client AES Key: {client_aes_key.hex()}")
    print(f"Server AES Key: {server_aes_key.hex()}")