from kyber_py.ml_kem import ML_KEM_1024

def generate_keys():
    ek, dk = ML_KEM_1024.keygen()
    return ek, dk


if __name__ == "__main__":
    ek, dk = generate_keys()