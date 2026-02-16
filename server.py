import socket
from common.config import SERVER_HOST, SERVER_PORT


def start_server():
   
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)

    print(f"[+] Server listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client, addr = server.accept()
        print(f"[+] Connection from {addr}")
        client.close()


if __name__ == "__main__":
    start_server()
