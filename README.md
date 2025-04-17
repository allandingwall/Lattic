# Lattic

**Lattic** is a proof-of-concept Python project implementing post-quantum key exchange using ML-KEM (Kyber) over the QUIC protocol.

## 🔐 Overview

- Post-quantum key exchange via [ML-KEM (Kyber)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- Transported over [QUIC](https://datatracker.ietf.org/doc/html/rfc9000) using the [`aioquic`](https://github.com/aiortc/aioquic) library
- Encrypted data transmission with AES-GCM using the shared Kyber secret

## 🚀 Features

- Client/server architecture
- QUIC handshake
- Kyber key encapsulation
- AES-encrypted data exchange
