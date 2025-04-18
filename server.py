import crypto_utils
import quic_handler

# ESTABLISH DSA KEY PAIR
DSA_PUB_KEY, DSA_SEC_KEY = crypto_utils.generate_dsa_keys()

# Await incoming connection


# Establish KEM key pair
encap_key, decap_key = crypto_utils.generate_kem_keys()
sig = crypto_utils.create_signature(DSA_SEC_KEY, encap_key)

# Send DSA public key and encapsulation key to client


# Await client response (containing ciphertext)
