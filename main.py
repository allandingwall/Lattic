from kyber_py.ml_kem import ML_KEM_1024

if __name__ == "__main__":
    ek, dk = ML_KEM_1024.keygen()
    key, ct = ML_KEM_1024.encaps(ek)
    _key = ML_KEM_1024.decaps(dk, ct)
    print(key.hex())