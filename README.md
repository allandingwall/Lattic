# Lattic

**Lattic** is a proof-of-concept Python project implementing post-quantum key exchange using ML-KEM (Kyber).

## Overview

- Post-quantum key exchange via [ML-KEM (Kyber)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- Encrypted data transmission with AES-GCM a key derived from the shared Kyber secret

## Features

- Client/server architecture
- Kyber key encapsulation
- AES-encrypted data exchange


# To Do
- Implement networking for key exchange.
- Implement command-line arguments to choose whether to act as a client or server, then consolidate client and server code into one file.
- Implement QUIC protocol for key exchange. The lower overhead of QUIC compared to TLS will enable a more efficient key exhange.