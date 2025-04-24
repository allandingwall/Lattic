# Lattic

**Lattic** is a proof-of-concept Python project implementing post-quantum key exchange using ML-KEM (Kyber).

## Overview

- Post-quantum key exchange via [ML-KEM (NIST FIPS 203)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf), signed with [ML-DSA (NIST FIPS 204)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) to prevent Man-In-The-Middle (MITM) attacks.
- Encrypted data transmission with AES-GCM between client and server using key derived from the shared Kyber secret.

## Features

- Client/server architecture
- Post-quantum key encapsulation mechanism coupled with post-quantum digital signatures.
- AES-encrypted data exchange

## Usage
*WIP*


## To Do
- Implement a database as a faux certificate authority (CA).
- Add in encrypted message functionality to client and server
- Combine client and server codebases into main codebase (lattic.py)
- Implement command-line arguments to choose whether to act as a client or server, then consolidate client and server code into one file.
- Implement QUIC protocol for key exchange. The lower overhead of QUIC compared to TLS will enable a more efficient key exhange.
- Write Usage section on README.
- Add hash visualisation function for verification of shared AES key.