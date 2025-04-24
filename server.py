import asyncio
import base64
import hashlib
import struct
import crypto_utils

async def send_message(writer, data: bytes):
    writer.write(struct.pack('!I', len(data)))
    writer.write(data)
    await writer.drain()

async def receive_message(reader) -> bytes:
    raw_len = await reader.readexactly(4)
    (length,) = struct.unpack('!I', raw_len)
    return await reader.readexactly(length)

async def establish_shared_key_server(reader, writer):
    dsa_pub_key, dsa_sec_key = crypto_utils.generate_dsa_keys()
    encap_key, decap_key = crypto_utils.generate_kem_keys()
    sig = crypto_utils.create_signature(dsa_sec_key, encap_key)

    await send_message(writer, base64.b64encode(encap_key))
    await send_message(writer, base64.b64encode(sig))

    ciphertext = base64.b64decode(await receive_message(reader))
    salt = base64.b64decode(await receive_message(reader))

    pq_key = crypto_utils.decapsulate_key(decap_key, ciphertext)
    aes_key = crypto_utils.derive_aes_key(salt, pq_key)

    print(f"Server AES Key hash: {hashlib.sha256(aes_key).hexdigest()}")
    return aes_key

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Connected to client at {addr}")

    try:
        await establish_shared_key_server(reader, writer)
    except Exception as e:
        print(f"Error during key exchange: {e}")

    writer.close()
    await writer.wait_closed()

async def run_server():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 8888)
    print("Server running on 127.0.0.1:8888")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(run_server())
