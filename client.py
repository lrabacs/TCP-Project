import hashlib
import struct

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
    # Request and display a file from the server.
    client_socket = TransportSocket(debug=False)

    try:
        print(f"Connecting to {SERVER_HOST}:{SERVER_PORT}...")
        client_socket.connect(SERVER_HOST, SERVER_PORT)

        print("Requesting file...")
        send_message(client_socket, b"GET_FILE")

        filename = recv_message(client_socket).decode("utf-8")
        file_data = recv_message(client_socket)
        server_hash = recv_message(client_socket).decode("utf-8")

        local_hash = hashlib.sha256(file_data).hexdigest()

        print()
        print(f"Received '{filename}' ({len(file_data)} bytes)")
        print()
        print("File contents:")
        print("-" * 50)

        try:
            print(file_data.decode("utf-8"))
        except UnicodeDecodeError:
            print("[Binary file received. Contents cannot be displayed as text.]")

        print("-" * 50)
        print()
        print(f"Server SHA-256: {server_hash}")
        print(f"Client SHA-256: {local_hash}")

        if server_hash == local_hash:
            print("Integrity check: PASS")
        else:
            print("Integrity check: FAIL")

    finally:
        client_socket.close()


if __name__ == "__main__":
    client_main()