# Notes
## QUIC
- aioquic

## ML-KEM
- kyber-py
    - https://github.com/GiacomoPope/kyber-py
		- There are four functions exposed on the ML_KEM class which are intended for use:
			* ML_KEM.keygen(): generate a keypair (ek, dk)
			* ML_KEM.key_derive(seed): generate a keypair (ek, dk) from the provided seed
			* ML_KEM.encaps(ek): generate a key and ciphertext pair (key, ct)
			* ML_KEM.decaps(dk, ct): generate the shared key key


HAVE TO IMPLEMENT MESSAGE SIGNATURES IN ORDER TO VERIFY. ML-KEM IS VULNERABLE TO MITM.
- https://www.reddit.com/r/cryptography/comments/1imyv5r/usage_of_mlkem/
    * “Neither pure/bare ephemeral ML-KEM nor pure/bare ephemeral ECDH provide authentication, therefore both would be vulnerable to Man-In-The-Middle attack. Ways to mitigate this risk (for either or both of the above):
        * Certify public keys involved (or pre-load them), so you can tell whether the public key you got to use in the Key Establishment, is “authentic”, aka - belongs to who you thought it did (rather than to an adversary that sits on the communications line between you and your peer); or 
        * explicitly sign the transcript exchange with ML-DSA or ECDSA correspondingly, again to make sure you’ve established your session with who you think you did..“


ML-KEM
A key-encapsulation mechanism (KEM) is a set of algorithms that, under certain conditions, can be used by two parties to establish a shared secret key over a public channel. A shared secret key that is securely established using a KEM can then be used with symmetric-key cryptographic algorithms to perform basic tasks in secure communications, such as encryption and authentication. This standard specifies a key-encapsulation mechanism called ML-KEM. The security of ML-KEM is related to the computational difficulty of the Module Learning with Errors problem. At present, ML-KEM is believed to be secure, even against adversaries who possess a quantum computer. This standard specifies three parameter sets for ML-KEM. In order of increasing security strength and decreasing performance, these are ML-KEM-512, ML-KEM-768, and ML-KEM-1024.


https://datatracker.ietf.org/doc/draft-celi-wiggers-tls-authkem/
Authentication in TLS 1.3 is achieved by signing the handshake transcript with digital signatures algorithms. KEM-based authentication provides authentication by deriving a shared secret that is encapsulated against the public key contained in the Certificate. Only the holder of the private key corresponding to the certificate's public key can derive the same shared secret and thus decrypt its peer's messages.


## ML-DSA
- dilithium-py
