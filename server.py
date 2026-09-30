import hashlib
import random
import string
import struct

from transport import TransportSocket


def generate_random_data(size):
    # Generate random bytes of the requested size
    return "".join(
        random.choices(string.ascii_letters + string.digits, k=size)
    ).encode()


def send_message(sock, data):
    # Send one length-prefixed application message
    header = struct.pack("!I", len(data))
    sock.send(header + data)


def recv_exact(sock, length):
    # Receive exactly length bytes unless the connection closes early
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
    # Receive one length-prefixed application message
    header = recv_exact(sock, 4)
    message_length = struct.unpack("!I", header)[0]

    return recv_exact(sock, message_length)


def server_main():
    # Listen for one client and test bidirectional reliable transfer
    server_socket = TransportSocket(debug=True)

    try:
        server_socket.listen(54321)

        print("Server: Waiting for client file...")
        client_file_data = recv_message(server_socket)

        print(
            f"Server: Received client file "
            f"({len(client_file_data)} bytes)"
        )

        print("Server: Waiting for client random data...")
        client_random_data = recv_message(server_socket)

        print(
            f"Server: Received {len(client_random_data)} bytes "
            f"of random data from client"
        )

        print(
            f"Server SHA-256 received: "
            f"{hashlib.sha256(client_random_data).hexdigest()}"
        )

        server_data = b"This is a test message from the server."

        print(
            f"Server: Sending test message "
            f"({len(server_data)} bytes)..."
        )

        send_message(server_socket, server_data)

        random_data = generate_random_data(100_000)

        print(
            f"Server: Sending {len(random_data)} bytes "
            f"of random data..."
        )

        print(
            f"Server SHA-256 sent: "
            f"{hashlib.sha256(random_data).hexdigest()}"
        )

        send_message(server_socket, random_data)

    finally:
        server_socket.close()


if __name__ == "__main__":
    server_main()