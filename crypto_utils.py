from kyber_py.ml_kem import ML_KEM_1024
from dilithium_py.ml_dsa import ML_DSA_87

def generate_kem_keys():
    ek, dk = ML_KEM_1024.keygen()
    return ek, dk

def derive_client_kem_key(ek):
    key, ct = ML_KEM_1024.encaps(ek)
    return key, ct

def derive_server_key(dk, ct):
    key = ML_KEM_1024.decaps(dk, ct)
    return key

def generate_dsa_keys():
    pk, sk = ML_DSA_87.keygen()
    return pk, sk

def create_signature(sk, msg):
    return ML_DSA_87.sign(sk, msg)

def verify_signature(pk, msg, sig):
    return ML_DSA_87.verify(pk, msg, sig)

if __name__ == "__main__":
    # SERVER
    pk, sk = generate_dsa_keys()
    ek, dk = generate_kem_keys()
    sig = create_signature(sk, ek)
    ## SEND PK, EK

    # CLIENT
    ## OBTAIN PK FROM CERTIFICATE AUTHORITY
    if verify_signature(pk, ek, sig):
        client_key, ct = derive_client_kem_key(ek)
        # SEND CT
    
    # SERVER
    server_key = derive_server_key(dk, ct)

    print(client_key == server_key)
