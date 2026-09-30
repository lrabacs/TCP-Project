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


def client_main():
    # Connect to the server and test bidirectional reliable transfer
    client_socket = TransportSocket(debug=True)

    try:
        client_socket.connect("127.0.0.1", 54321)

        file_name = "sample_data.txt"

        with open(file_name, "rb") as file:
            file_data = file.read()

        print(f"Client: Sending '{file_name}' ({len(file_data)} bytes)...")
        send_message(client_socket, file_data)

        random_data = generate_random_data(100_000)

        print(
            f"Client SHA-256 sent: "
            f"{hashlib.sha256(random_data).hexdigest()}"
        )

        print(
            f"Client: Sending {len(random_data)} bytes "
            f"of random data..."
        )

        send_message(client_socket, random_data)

        print("Client: Waiting for server file...")
        server_file_data = recv_message(client_socket)

        print(
            f"Client: Received server file "
            f"({len(server_file_data)} bytes):\n"
            f"{server_file_data.decode()}"
        )

        print("Client: Waiting for server random data...")
        server_random_data = recv_message(client_socket)

        print(
            f"Client: Received {len(server_random_data)} bytes "
            f"of random data from server"
        )

        print(
            f"Client SHA-256 received: "
            f"{hashlib.sha256(server_random_data).hexdigest()}"
        )

    finally:
        client_socket.close()


if __name__ == "__main__":
    client_main()