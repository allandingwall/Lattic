import asyncio
import struct

async def send_message(writer, data: bytes):
    writer.write(struct.pack('!I', len(data)))
    writer.write(data)
    await writer.drain()

async def receive_message(reader) -> bytes:
    raw_len = await reader.readexactly(4)
    (length,) = struct.unpack('!I', raw_len)
    return await reader.readexactly(length)