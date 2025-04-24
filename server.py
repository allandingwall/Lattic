import asyncio
import base64
import crypto_utils
import hashlib

print("Generating signing keys...")
dsa_pub_key, dsa_sec_key =crypto_utils.generate_dsa_keys()
print(f"Server Public Signing Key hash: {hashlib.sha256(dsa_pub_key).hexdigest()}\n")


async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Connected to client on {addr}")
    encap_key, decap_key = crypto_utils.generate_kem_keys()
    sig = crypto_utils.create_signature(dsa_sec_key, encap_key)
    print("Sending signature and encapsulation key to client...\n")

    message = f"{encap_key.hex()};{sig.hex()}"
    writer.write(message.encode())
    await writer.drain()



    while True:
        data = await reader.read(2048)
        if not data:
            break
        message = data.decode()
        print(f"Received {message!r} from {addr}")

        response = f"Echo: {message}"
        writer.write(response.encode())
        await writer.drain()

    print(f"Closing connection with {addr}")
    writer.close()
    await writer.wait_closed()

async def run_server():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 8888)
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Serving on {addrs}")

    async with server:
        await server.serve_forever()

# Run the server
if __name__ == "__main__":
    asyncio.run(run_server())
