import asyncio


async def run_client():
    reader, writer = await asyncio.open_connection("127.0.0.1", 8888)
    data = await reader.read(16384)
    data = (data.decode()).split(";")

    print("Closing the connection")
    writer.close()
    await writer.wait_closed()

# Run the client
if __name__ == "__main__":
    asyncio.run(run_client())
