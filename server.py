import hashlib
import struct
from pathlib import Path

from transport import TransportSocket


SERVER_PORT = 54321
FILE_TO_SERVE = Path("sample_data.txt")


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


def server_main():
    # Serve a file to one connected client.
    if not FILE_TO_SERVE.is_file():
        print(f"File not found: {FILE_TO_SERVE}")
        return

    file_data = FILE_TO_SERVE.read_bytes()
    file_hash = hashlib.sha256(file_data).hexdigest()

    server_socket = TransportSocket(debug=False)

    try:
        print(f"Listening on port {SERVER_PORT}...")
        server_socket.listen(SERVER_PORT)

        print("Client connected.")

        request = recv_message(server_socket).decode("utf-8")

        if request != "GET_FILE":
            raise ValueError(f"Unknown client request: {request}")

        print(
            f"Sending '{FILE_TO_SERVE.name}' "
            f"({len(file_data)} bytes)..."
        )

        send_message(
            server_socket,
            FILE_TO_SERVE.name.encode("utf-8")
        )

        send_message(
            server_socket,
            file_data
        )

        send_message(
            server_socket,
            file_hash.encode("utf-8")
        )

        print("File sent successfully.")
        print(f"SHA-256: {file_hash}")

    finally:
        server_socket.close()


if __name__ == "__main__":
    server_main()