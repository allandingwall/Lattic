from kyber_py.ml_kem import ML_KEM_1024
from dilithium_py.ml_dsa import ML_DSA_87

def generate_kem_keys():
    encap_key, decap_key = ML_KEM_1024.keygen()
    return encap_key, decap_key

def encapsulate_key(encap_key):
    key, ciphertext = ML_KEM_1024.encaps(encap_key)
    return key, ciphertext

def decapsulate_key(decap_key, ciphertext):
    key = ML_KEM_1024.decaps(decap_key, ciphertext)
    return key

def generate_dsa_keys():
    dsa_pub_key, dsa_sec_key = ML_DSA_87.keygen()
    return dsa_pub_key, dsa_sec_key

def create_signature(dsa_sec_key, msg):
    return ML_DSA_87.sign(dsa_sec_key, msg)

def verify_signature(pk, msg, sig):
    return ML_DSA_87.verify(pk, msg, sig)

if __name__ == "__main__":
    # SERVER
    dsa_pub_key, dsa_sec_key = generate_dsa_keys()
    encap_key, decap_key = generate_kem_keys()
    sig = create_signature(dsa_sec_key, encap_key)
    ## SEND PK, EK TO CLIENT

    # CLIENT
    ## OBTAIN PK FROM CERTIFICATE AUTHORITY
    if verify_signature(dsa_pub_key, encap_key, sig):
        client_key, ciphertext = encapsulate_key(encap_key)
        ## SEND CIPHERTEXT BACK TO SERVER
    else:
        raise Exception("Signature verification failed")
    
    # SERVER
    server_key = decapsulate_key(decap_key, ciphertext)

    print(f"Client Key: {client_key.hex()}")
    print(f"Server Key: {server_key.hex()}")

    ## TO DO: DERIVE SHARED AES KEY