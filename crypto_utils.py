import os
import hashlib
from kyber_py.ml_kem import ML_KEM_1024
from dilithium_py.ml_dsa import ML_DSA_87
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_dsa_keys():
    dsa_pub_key, dsa_sec_key = ML_DSA_87.keygen()
    # ADD IN LOGIC TO SEND PUBLIC KEY TO THE DATABASE (CERTIFICATE AUTHORITY)
    return dsa_pub_key, dsa_sec_key

def create_signature(dsa_sec_key, msg):
    return ML_DSA_87.sign(dsa_sec_key, msg)

def verify_signature(pk, msg, sig):
    return ML_DSA_87.verify(pk, msg, sig)

def generate_kem_keys():
    print("Generating encapsulation and decapsulation keys...")
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
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(bytes(shared_key))

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    try:
        kdf.verify(shared_key, key)
        return key
    
    except:
        raise Exception("Key derivation failed")
    
def encrypt_message(msg, aes_key):
    msg = msg.encode()
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, msg, None)
    payload = nonce + ciphertext
    return payload

def decrypt_message(payload, aes_key):
    nonce, ciphertext = payload[:12], payload[12:]
    aesgcm = AESGCM(aes_key)
    return (aesgcm.decrypt(nonce, ciphertext, None)).decode()

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

    print()
    print(server_aes_key)
    server_message = "Hello mate!"
    print(f"Server message: {server_message}")
    payload = encrypt_message(server_message, server_aes_key)
    print(f"Client encrypted payload: {payload}")

    # SENC ENC TO CLIENT
    print(f"Server encrypted payload: {payload}")
    client_message = decrypt_message(payload, client_aes_key)
    print(f"Client message: {client_message}")
