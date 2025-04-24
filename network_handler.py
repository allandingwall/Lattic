import asyncio
import struct
import base64
import os
import hashlib
import crypto_utils

async def send_message(writer, data: bytes):
    writer.write(struct.pack('!I', len(data)))
    writer.write(data)
    await writer.drain()

async def receive_message(reader) -> bytes:
    raw_len = await reader.readexactly(4)
    (length,) = struct.unpack('!I', raw_len)
    return await reader.readexactly(length)

async def establish_shared_key_client(reader, writer):
    encap_key = base64.b64decode(await receive_message(reader))
    sig = base64.b64decode(await receive_message(reader))

    pq_key, ciphertext = crypto_utils.encapsulate_key(encap_key)
    salt = os.urandom(16)

    aes_key = crypto_utils.derive_aes_key(salt, pq_key)

    await send_message(writer, base64.b64encode(ciphertext))
    await send_message(writer, base64.b64encode(salt))

    print(f"Client AES Key hash: {hashlib.sha256(aes_key).hexdigest()}")
    return aes_key

