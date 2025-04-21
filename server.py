import socket

HOST = "127.0.0.1"
PORT = 31459

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
print(f"Socket bound to {PORT}.")
s.listen()
print("Socket listening...")
conn, addr = s.accept()

with conn:
    print(f"Connected by {addr}")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        conn.sendall(data)