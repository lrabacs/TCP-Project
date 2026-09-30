import hashlib
import struct
from pathlib import Path

from transport import TransportSocket


SERVER_PORT = 54321
OUTPUT_DIRECTORY = Path("received_files")


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
    # Receive one file and save it using the reliable transport protocol.
    server_socket = TransportSocket(debug=True)

    try:
        print(f"Listening on port {SERVER_PORT}...")
        server_socket.listen(SERVER_PORT)

        print("Client connected.")

        filename = recv_message(server_socket).decode("utf-8")
        filename = Path(filename).name

        file_data = recv_message(server_socket)

        OUTPUT_DIRECTORY.mkdir(exist_ok=True)

        output_path = OUTPUT_DIRECTORY / filename
        output_path.write_bytes(file_data)

        file_hash = hashlib.sha256(file_data).hexdigest()

        print(
            f"Received '{filename}' "
            f"({len(file_data)} bytes)"
        )

        print(f"Saved to: {output_path}")
        print(f"SHA-256: {file_hash}")

        response = (
            f"Transfer complete\n"
            f"Server saved: {output_path}\n"
            f"Bytes received: {len(file_data)}\n"
            f"Server SHA-256: {file_hash}"
        )

        send_message(
            server_socket,
            response.encode("utf-8")
        )

    finally:
        server_socket.close()


if __name__ == "__main__":
    server_main()