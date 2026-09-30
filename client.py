import hashlib
import struct
import sys
from pathlib import Path

from transport import TransportSocket


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 54321


def send_message(sock, data):
    # Send one length-prefixed application message.
    header = struct.pack("!I", len(data))
    sock.send(header + data)


def recv_exact(sock, length):
    # Receive exactly length bytes unless the connection closes early.
    data = bytearray()

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError(
                "Connection closed before all expected data arrived"
            )

        data.extend(chunk)

    return bytes(data)


def recv_message(sock):
    # Receive one length-prefixed application message.
    header = recv_exact(sock, 4)
    message_length = struct.unpack("!I", header)[0]

    return recv_exact(sock, message_length)


def client_main():
    # Send a file to the server using the reliable transport protocol.
    if len(sys.argv) > 2:
        print("Usage: python client.py [file]")
        return

    file_path = Path(sys.argv[1] if len(sys.argv) == 2 else "sample_data.txt")

    if not file_path.is_file():
        print(f"File not found: {file_path}")
        return

    file_data = file_path.read_bytes()
    file_hash = hashlib.sha256(file_data).hexdigest()

    client_socket = TransportSocket(debug=True)

    try:
        print(f"Connecting to {SERVER_HOST}:{SERVER_PORT}...")
        client_socket.connect(SERVER_HOST, SERVER_PORT)

        print(f"Sending '{file_path.name}' ({len(file_data)} bytes)...")

        send_message(
            client_socket,
            file_path.name.encode("utf-8")
        )

        send_message(
            client_socket,
            file_data
        )

        response = recv_message(client_socket).decode("utf-8")

        print()
        print(response)
        print(f"Local SHA-256: {file_hash}")

    finally:
        client_socket.close()


if __name__ == "__main__":
    client_main()