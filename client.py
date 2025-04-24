import asyncio
import crypto_utils

print("Server generating signing keys...")
dsa_pub_key, dsa_sec_key =crypto_utils.generate_dsa_keys()

async def run_client():
    reader, writer = await asyncio.open_connection("127.0.0.1", 8888)
    data = await reader.read(1024)



    message = "NEW SESSION"
    print(f"Sending: {message}")
    writer.write(message.encode())
    await writer.drain()

    
    print(f"Received: {data.decode()}")

    print("Closing the connection")
    writer.close()
    await writer.wait_closed()

# Run the client
if __name__ == "__main__":
    asyncio.run(run_client())
