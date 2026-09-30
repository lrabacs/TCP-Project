import hashlib
import multiprocessing
import select
import socket
import struct
import threading
import time

from config import (
    DUPLICATE_ACK_THRESHOLD,
    MAX_NETWORK_BUFFER,
    MSS,
    PACKET_HEADER_FORMAT
)
from transport import (
    ACK_FLAG,
    CLOSED,
    EXIT_SUCCESS,
    FAST_RECOVERY,
    FIN_FLAG,
    SYN_FLAG,
    TransportSocket
)


HOST = "127.0.0.1"

NORMAL_PAYLOAD_SIZE = 100_000
FLOW_CONTROL_PAYLOAD_SIZE = 150_000

PROCESS_TIMEOUT = 15.0

HEADER_SIZE = struct.calcsize(PACKET_HEADER_FORMAT)


class InstrumentedTransportSocket(TransportSocket):
    def __init__(self, debug=False):
        # Track transport events that the automated tests need to verify.
        super().__init__(debug=debug)

        self.timeout_seen = False
        self.fast_retransmit_seen = False

        self.zero_window_seen = False
        self.window_reopened_seen = False

        self._window_monitor_stop = threading.Event()
        self._window_monitor_thread = None

    def _handle_timeout(self):
        # Record that timeout-based retransmission occurred.
        self.timeout_seen = True
        super()._handle_timeout()

    def _handle_duplicate_ack(self):
        # Record entry into Reno fast retransmit and fast recovery.
        super()._handle_duplicate_ack()

        if (
            self.dup_ack_count >= DUPLICATE_ACK_THRESHOLD
            and self.cc_state == FAST_RECOVERY
        ):
            self.fast_retransmit_seen = True

    def start_window_monitor(self):
        # Monitor every advertised-window update seen by the transport backend.
        self.zero_window_seen = False
        self.window_reopened_seen = False
        self._window_monitor_stop.clear()

        def monitor():
            saw_zero = False

            while not self._window_monitor_stop.is_set():
                current_window = self.peer_adv_window

                if current_window == 0:
                    saw_zero = True
                    self.zero_window_seen = True

                elif saw_zero and current_window > 0:
                    self.window_reopened_seen = True

                time.sleep(0.001)

        self._window_monitor_thread = threading.Thread(
            target=monitor,
            daemon=True
        )

        self._window_monitor_thread.start()

    def stop_window_monitor(self):
        # Stop monitoring receiver-window changes.
        self._window_monitor_stop.set()

        if self._window_monitor_thread is not None:
            self._window_monitor_thread.join(timeout=1.0)

        self._window_monitor_thread = None


class UDPProxy:
    def __init__(self, listen_port, server_port, mode=None):
        # Create a UDP proxy capable of dropping selected transport packets.
        self.listen_port = listen_port
        self.server_port = server_port
        self.mode = mode

        self.client_socket = None
        self.server_socket = None
        self.client_address = None

        self.stop_event = threading.Event()
        self.thread = None

        self.data_packet_count = 0
        self.dropped = False
        self.dropped_description = None

    def start(self):
        # Start forwarding traffic in a background thread.
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.client_socket.bind((HOST, self.listen_port))
        self.server_socket.bind((HOST, 0))

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        # Stop the forwarding thread and close both UDP sockets.
        self.stop_event.set()

        if self.thread:
            self.thread.join(timeout=1.0)

        if self.client_socket:
            self.client_socket.close()

        if self.server_socket:
            self.server_socket.close()

    def _packet_info(self, data):
        # Decode enough of a transport packet for loss rules.
        if len(data) < HEADER_SIZE:
            return None

        try:
            return struct.unpack(
                PACKET_HEADER_FORMAT,
                data[:HEADER_SIZE]
            )
        except struct.error:
            return None

    def _should_drop_client_packet(self, data):
        # Decide whether this client-to-server packet should be dropped.
        info = self._packet_info(data)

        if info is None:
            return False

        seq, ack, flags, payload_length, advertised_window = info

        if payload_length > 0:
            self.data_packet_count += 1

        if self.dropped:
            return False

        if self.mode == "first_data":
            if payload_length > 0:
                self.dropped = True
                self.dropped_description = (
                    f"data packet seq={seq}, payload={payload_length}"
                )
                return True

        elif self.mode == "middle_data":
            if payload_length > 0 and self.data_packet_count == 20:
                self.dropped = True
                self.dropped_description = (
                    f"middle data packet seq={seq}, "
                    f"payload={payload_length}"
                )
                return True

        elif self.mode == "first_syn":
            if (
                flags & SYN_FLAG
                and not flags & ACK_FLAG
                and payload_length == 0
            ):
                self.dropped = True
                self.dropped_description = "first SYN"
                return True

        elif self.mode == "first_fin":
            if flags & FIN_FLAG:
                self.dropped = True
                self.dropped_description = "first FIN"
                return True

        return False

    def _run(self):
        # Forward UDP packets between the client and server.
        server_address = (HOST, self.server_port)

        while not self.stop_event.is_set():
            try:
                readable, _, _ = select.select(
                    [self.client_socket, self.server_socket],
                    [],
                    [],
                    0.1
                )
            except (OSError, ValueError):
                break

            for sock in readable:
                if sock is self.client_socket:
                    try:
                        data, address = self.client_socket.recvfrom(65535)
                    except OSError:
                        continue

                    self.client_address = address

                    if self._should_drop_client_packet(data):
                        continue

                    try:
                        self.server_socket.sendto(data, server_address)
                    except OSError:
                        continue

                else:
                    try:
                        data, _ = self.server_socket.recvfrom(65535)
                    except OSError:
                        continue

                    if self.client_address is not None:
                        try:
                            self.client_socket.sendto(
                                data,
                                self.client_address
                            )
                        except OSError:
                            continue


def generate_data(size, seed):
    # Generate deterministic bytes so transfer integrity can be verified.
    return bytes(
        ((index * 31) + seed) % 256
        for index in range(size)
    )


def sha256(data):
    # Return the SHA-256 digest of a byte string.
    return hashlib.sha256(data).hexdigest()


def recv_exact(sock, length):
    # Receive exactly the requested number of bytes.
    data = bytearray()

    while len(data) < length:
        chunk = sock.recv(
            min(4096, length - len(data))
        )

        if not chunk:
            raise ConnectionError(
                "Connection closed before expected data arrived"
            )

        data.extend(chunk)

    return bytes(data)


def get_free_udp_port():
    # Ask the operating system for an unused local UDP port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, 0))

    port = sock.getsockname()[1]
    sock.close()

    return port


def get_two_free_ports():
    # Get two different UDP ports.
    first = get_free_udp_port()
    second = get_free_udp_port()

    while second == first:
        second = get_free_udp_port()

    return first, second


def queue_result(queue, **kwargs):
    # Place one worker result into its multiprocessing queue.
    queue.put(kwargs)


def clean_server(port, size, ready_event, result_queue):
    # Receive and send a large payload over a clean connection.
    sock = TransportSocket(debug=False)

    try:
        sock.listen(port)
        ready_event.set()

        client_data = recv_exact(sock, size)

        server_data = generate_data(size, 22)
        sock.send(server_data)

        close_result = sock.close()

        queue_result(
            result_queue,
            success=True,
            received_hash=sha256(client_data),
            sent_hash=sha256(server_data),
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        ready_event.set()

        queue_result(
            result_queue,
            success=False,
            error=repr(exc)
        )


def clean_client(port, size, result_queue):
    # Send and receive a large payload over a clean connection.
    sock = TransportSocket(debug=False)

    try:
        sock.connect(HOST, port)

        client_data = generate_data(size, 11)
        sock.send(client_data)

        server_data = recv_exact(sock, size)

        close_result = sock.close()

        queue_result(
            result_queue,
            success=True,
            sent_hash=sha256(client_data),
            received_hash=sha256(server_data),
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        queue_result(
            result_queue,
            success=False,
            error=repr(exc)
        )


def one_way_server(port, size, ready_event, result_queue):
    # Receive one large payload and return a short confirmation.
    sock = TransportSocket(debug=False)

    try:
        sock.listen(port)
        ready_event.set()

        data = recv_exact(sock, size)
        sock.send(b"OK")

        close_result = sock.close()

        queue_result(
            result_queue,
            success=True,
            received_hash=sha256(data),
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        ready_event.set()

        queue_result(
            result_queue,
            success=False,
            error=repr(exc)
        )


def instrumented_client(port, size, result_queue):
    # Send a large payload while recording retransmission behavior.
    sock = InstrumentedTransportSocket(debug=False)

    try:
        sock.connect(HOST, port)

        data = generate_data(size, 33)
        sock.send(data)

        response = recv_exact(sock, 2)

        close_result = sock.close()

        queue_result(
            result_queue,
            success=response == b"OK",
            sent_hash=sha256(data),
            timeout_seen=sock.timeout_seen,
            fast_retransmit_seen=sock.fast_retransmit_seen,
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        queue_result(
            result_queue,
            success=False,
            error=repr(exc),
            timeout_seen=sock.timeout_seen,
            fast_retransmit_seen=sock.fast_retransmit_seen
        )


def handshake_server(port, ready_event, result_queue):
    # Verify a connection and small transfer after handshake recovery.
    sock = TransportSocket(debug=False)

    try:
        sock.listen(port)
        ready_event.set()

        data = recv_exact(sock, 4)

        if data != b"ping":
            raise ValueError("Server received incorrect handshake-test data")

        sock.send(b"pong")

        close_result = sock.close()

        queue_result(
            result_queue,
            success=True,
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        ready_event.set()

        queue_result(
            result_queue,
            success=False,
            error=repr(exc)
        )


def handshake_client(port, result_queue):
    # Connect through a proxy that drops the first SYN.
    sock = TransportSocket(debug=False)

    try:
        sock.connect(HOST, port)

        sock.send(b"ping")
        response = recv_exact(sock, 4)

        close_result = sock.close()

        queue_result(
            result_queue,
            success=response == b"pong",
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        queue_result(
            result_queue,
            success=False,
            error=repr(exc)
        )


def flow_server(port, size, ready_event, result_queue):
    # Delay application reads long enough to fill the transport receive window.
    sock = TransportSocket(debug=False)

    try:
        sock.listen(port)
        ready_event.set()

        time.sleep(1.0)

        data = recv_exact(sock, size)

        sock.send(b"OK")

        close_result = sock.close()

        queue_result(
            result_queue,
            success=True,
            received_hash=sha256(data),
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        ready_event.set()

        queue_result(
            result_queue,
            success=False,
            error=repr(exc)
        )


def flow_client(port, size, result_queue):
    # Verify sender pause and recovery when the receiver window reaches zero.
    sock = InstrumentedTransportSocket(debug=False)

    try:
        sock.connect(HOST, port)

        data = generate_data(size, 44)

        sock.start_window_monitor()

        sock.send(data)

        response = recv_exact(sock, 2)

        sock.stop_window_monitor()

        close_result = sock.close()

        queue_result(
            result_queue,
            success=response == b"OK",
            sent_hash=sha256(data),
            zero_window_seen=sock.zero_window_seen,
            window_reopened_seen=sock.window_reopened_seen,
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        sock.stop_window_monitor()

        queue_result(
            result_queue,
            success=False,
            error=repr(exc),
            zero_window_seen=sock.zero_window_seen,
            window_reopened_seen=sock.window_reopened_seen
        )


def fin_server(port, ready_event, result_queue):
    # Wait for the client to close after exchanging a short message.
    sock = TransportSocket(debug=False)

    try:
        sock.listen(port)
        ready_event.set()

        data = recv_exact(sock, 4)

        if data != b"ping":
            raise ValueError("Server received incorrect FIN-test data")

        sock.send(b"pong")

        eof = sock.recv(1)

        close_result = sock.close()

        queue_result(
            result_queue,
            success=eof == b"",
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        ready_event.set()

        queue_result(
            result_queue,
            success=False,
            error=repr(exc)
        )


def fin_client(port, result_queue):
    # Close normally while the proxy drops the first FIN.
    sock = TransportSocket(debug=False)

    try:
        sock.connect(HOST, port)

        sock.send(b"ping")
        response = recv_exact(sock, 4)

        close_result = sock.close()

        queue_result(
            result_queue,
            success=response == b"pong",
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        queue_result(
            result_queue,
            success=False,
            error=repr(exc)
        )


def malformed_server(port, ready_event, result_queue):
    # Verify malformed datagrams do not kill the listener backend.
    sock = TransportSocket(debug=False)

    try:
        sock.listen(port)
        ready_event.set()

        data = recv_exact(sock, 4)

        if data != b"ping":
            raise ValueError("Server received incorrect malformed-test data")

        sock.send(b"pong")

        close_result = sock.close()

        queue_result(
            result_queue,
            success=True,
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        ready_event.set()

        queue_result(
            result_queue,
            success=False,
            error=repr(exc)
        )


def malformed_client(port, result_queue):
    # Connect normally after malformed packets have been injected.
    sock = TransportSocket(debug=False)

    try:
        sock.connect(HOST, port)

        sock.send(b"ping")
        response = recv_exact(sock, 4)

        close_result = sock.close()

        queue_result(
            result_queue,
            success=response == b"pong",
            close_result=close_result,
            state=sock.state
        )

    except Exception as exc:
        queue_result(
            result_queue,
            success=False,
            error=repr(exc)
        )


def inject_malformed_packets(port):
    # Send several malformed UDP datagrams directly to the listener.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.sendto(
            b"\x00\x01",
            (HOST, port)
        )

        oversized_header = struct.pack(
            PACKET_HEADER_FORMAT,
            0,
            0,
            ACK_FLAG,
            MSS + 1,
            MAX_NETWORK_BUFFER
        )

        sock.sendto(
            oversized_header,
            (HOST, port)
        )

        incorrect_length_header = struct.pack(
            PACKET_HEADER_FORMAT,
            0,
            0,
            ACK_FLAG,
            100,
            MAX_NETWORK_BUFFER
        )

        sock.sendto(
            incorrect_length_header,
            (HOST, port)
        )

    finally:
        sock.close()


def terminate_process(process):
    # Terminate a worker that failed to finish within the test timeout.
    if process.is_alive():
        process.terminate()
        process.join(timeout=2.0)


def read_result(queue):
    # Return one worker result or a synthetic failure result.
    try:
        return queue.get(timeout=1.0)
    except Exception:
        return {
            "success": False,
            "error": "Worker returned no result"
        }


def run_workers(server_target, server_args, client_target, client_args):
    # Start a server and client process and collect both results.
    ready_event = multiprocessing.Event()

    server_queue = multiprocessing.Queue()
    client_queue = multiprocessing.Queue()

    server_process = multiprocessing.Process(
        target=server_target,
        args=(
            *server_args,
            ready_event,
            server_queue
        )
    )

    server_process.start()

    if not ready_event.wait(timeout=3.0):
        terminate_process(server_process)

        return (
            {"success": False, "error": "Server did not become ready"},
            {"success": False, "error": "Client was not started"}
        )

    client_process = multiprocessing.Process(
        target=client_target,
        args=(
            *client_args,
            client_queue
        )
    )

    client_process.start()

    server_process.join(timeout=PROCESS_TIMEOUT)
    client_process.join(timeout=PROCESS_TIMEOUT)

    terminate_process(server_process)
    terminate_process(client_process)

    server_result = read_result(server_queue)
    client_result = read_result(client_queue)

    return server_result, client_result


def run_proxy_workers(
    proxy_mode,
    server_target,
    server_args,
    client_target,
    client_args
):
    # Run one server/client test through a packet-loss proxy.
    server_port, proxy_port = get_two_free_ports()

    ready_event = multiprocessing.Event()

    server_queue = multiprocessing.Queue()
    client_queue = multiprocessing.Queue()

    server_process = multiprocessing.Process(
        target=server_target,
        args=(
            server_port,
            *server_args,
            ready_event,
            server_queue
        )
    )

    server_process.start()

    if not ready_event.wait(timeout=3.0):
        terminate_process(server_process)

        return (
            {"success": False, "error": "Server did not become ready"},
            {"success": False, "error": "Client was not started"},
            None
        )

    proxy = UDPProxy(
        listen_port=proxy_port,
        server_port=server_port,
        mode=proxy_mode
    )

    proxy.start()

    client_process = multiprocessing.Process(
        target=client_target,
        args=(
            proxy_port,
            *client_args,
            client_queue
        )
    )

    client_process.start()

    server_process.join(timeout=PROCESS_TIMEOUT)
    client_process.join(timeout=PROCESS_TIMEOUT)

    terminate_process(server_process)
    terminate_process(client_process)

    proxy.stop()

    server_result = read_result(server_queue)
    client_result = read_result(client_queue)

    return server_result, client_result, proxy


def test_clean_transfer():
    # Verify a clean 100 KB transfer in both directions.
    port = get_free_udp_port()

    server_result, client_result = run_workers(
        clean_server,
        (port, NORMAL_PAYLOAD_SIZE),
        clean_client,
        (port, NORMAL_PAYLOAD_SIZE)
    )

    passed = (
        server_result.get("success")
        and client_result.get("success")
        and client_result.get("sent_hash")
        == server_result.get("received_hash")
        and server_result.get("sent_hash")
        == client_result.get("received_hash")
        and server_result.get("close_result") == EXIT_SUCCESS
        and client_result.get("close_result") == EXIT_SUCCESS
        and server_result.get("state") == CLOSED
        and client_result.get("state") == CLOSED
    )

    return passed, None


def test_timeout_retransmission():
    # Drop the first data packet so recovery must wait for the retransmission timer.
    server_result, client_result, proxy = run_proxy_workers(
        "first_data",
        one_way_server,
        (NORMAL_PAYLOAD_SIZE,),
        instrumented_client,
        (NORMAL_PAYLOAD_SIZE,)
    )

    passed = (
        proxy is not None
        and proxy.dropped
        and server_result.get("success")
        and client_result.get("success")
        and client_result.get("sent_hash")
        == server_result.get("received_hash")
        and client_result.get("timeout_seen") is True
        and server_result.get("state") == CLOSED
        and client_result.get("state") == CLOSED
    )

    detail = None

    if proxy is not None:
        detail = proxy.dropped_description

    return passed, detail


def test_fast_retransmit():
    # Drop a middle packet after the congestion window has grown.
    server_result, client_result, proxy = run_proxy_workers(
        "middle_data",
        one_way_server,
        (NORMAL_PAYLOAD_SIZE,),
        instrumented_client,
        (NORMAL_PAYLOAD_SIZE,)
    )

    passed = (
        proxy is not None
        and proxy.dropped
        and server_result.get("success")
        and client_result.get("success")
        and client_result.get("sent_hash")
        == server_result.get("received_hash")
        and client_result.get("fast_retransmit_seen") is True
        and server_result.get("state") == CLOSED
        and client_result.get("state") == CLOSED
    )

    detail = None

    if proxy is not None:
        detail = proxy.dropped_description

    return passed, detail


def test_handshake_loss():
    # Drop the first SYN and verify connection establishment still succeeds.
    server_result, client_result, proxy = run_proxy_workers(
        "first_syn",
        handshake_server,
        (),
        handshake_client,
        ()
    )

    passed = (
        proxy is not None
        and proxy.dropped
        and server_result.get("success")
        and client_result.get("success")
        and server_result.get("state") == CLOSED
        and client_result.get("state") == CLOSED
    )

    detail = None

    if proxy is not None:
        detail = proxy.dropped_description

    return passed, detail


def test_flow_control():
    # Fill the receiver buffer and verify the sender resumes after window reopening.
    port = get_free_udp_port()

    server_result, client_result = run_workers(
        flow_server,
        (port, FLOW_CONTROL_PAYLOAD_SIZE),
        flow_client,
        (port, FLOW_CONTROL_PAYLOAD_SIZE)
    )

    passed = (
        server_result.get("success")
        and client_result.get("success")
        and client_result.get("sent_hash")
        == server_result.get("received_hash")
        and client_result.get("zero_window_seen") is True
        and client_result.get("window_reopened_seen") is True
        and server_result.get("state") == CLOSED
        and client_result.get("state") == CLOSED
    )

    return passed, None


def test_fin_loss():
    # Drop the first client FIN and verify teardown succeeds after retransmission.
    server_result, client_result, proxy = run_proxy_workers(
        "first_fin",
        fin_server,
        (),
        fin_client,
        ()
    )

    passed = (
        proxy is not None
        and proxy.dropped
        and server_result.get("success")
        and client_result.get("success")
        and server_result.get("state") == CLOSED
        and client_result.get("state") == CLOSED
    )

    detail = None

    if proxy is not None:
        detail = proxy.dropped_description

    return passed, detail


def test_malformed_packets():
    # Inject malformed UDP data, then verify the listener still handles a real client.
    port = get_free_udp_port()

    ready_event = multiprocessing.Event()

    server_queue = multiprocessing.Queue()
    client_queue = multiprocessing.Queue()

    server_process = multiprocessing.Process(
        target=malformed_server,
        args=(
            port,
            ready_event,
            server_queue
        )
    )

    server_process.start()

    if not ready_event.wait(timeout=3.0):
        terminate_process(server_process)

        return False, "Server did not become ready"

    inject_malformed_packets(port)

    time.sleep(0.2)

    client_process = multiprocessing.Process(
        target=malformed_client,
        args=(
            port,
            client_queue
        )
    )

    client_process.start()

    server_process.join(timeout=PROCESS_TIMEOUT)
    client_process.join(timeout=PROCESS_TIMEOUT)

    terminate_process(server_process)
    terminate_process(client_process)

    server_result = read_result(server_queue)
    client_result = read_result(client_queue)

    passed = (
        server_result.get("success")
        and client_result.get("success")
        and server_result.get("state") == CLOSED
        and client_result.get("state") == CLOSED
    )

    return passed, None


def main():
    # Run the complete reliable-transport integration suite.
    tests = [
        ("Clean 100 KB bidirectional transfer", test_clean_transfer),
        ("Timeout retransmission", test_timeout_retransmission),
        ("Middle-packet loss / fast retransmit", test_fast_retransmit),
        ("Handshake loss recovery", test_handshake_loss),
        ("Zero-window flow-control recovery", test_flow_control),
        ("FIN loss / teardown recovery", test_fin_loss),
        ("Malformed packet handling", test_malformed_packets)
    ]

    passed_count = 0

    print()
    print("Reliable Transport Protocol Test Suite")
    print("=" * 50)

    for index, (name, test_function) in enumerate(tests, start=1):
        print(f"[{index}/{len(tests)}] {name} ... ", end="", flush=True)

        try:
            passed, detail = test_function()
        except Exception as exc:
            passed = False
            detail = repr(exc)

        if passed:
            passed_count += 1
            print("PASS")

            if detail:
                print(f"      Dropped: {detail}")

        else:
            print("FAIL")

            if detail:
                print(f"      {detail}")

    print("=" * 50)
    print(f"{passed_count}/{len(tests)} tests passed")

    if passed_count == len(tests):
        print("All transport integration tests passed.")
    else:
        print("One or more tests exposed behavior we need to inspect.")
        raise SystemExit(1)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()