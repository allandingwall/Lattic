import asyncio
import crypto_utils
import hashlib

print("Server generating signing keys...")
dsa_pub_key, dsa_sec_key =crypto_utils.generate_dsa_keys()
print(f"Server Public Signing Key hash: {hashlib.sha256(dsa_pub_key).hexdigest()}")


async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Connected to {addr}")






    while True:
        data = await reader.read(2048)
        if not data:
            break
        print("Client connected")
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
