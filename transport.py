import socket
import struct
import threading
import time

from config import (
    DEFAULT_TIMEOUT,
    DUPLICATE_ACK_THRESHOLD,
    HANDSHAKE_RETRY_INTERVAL,
    MAX_CLOSE_DURATION,
    MAX_DATA_RETRIES,
    MAX_FIN_RETRIES,
    MAX_HANDSHAKE_RETRIES,
    MAX_NETWORK_BUFFER,
    MAX_RTO,
    MIN_RTO,
    MSS,
    PACKET_HEADER_FORMAT,
    TIME_WAIT_DURATION,
    WINDOW_INITIAL_SSTHRESH,
    WINDOW_INITIAL_WINDOW_SIZE,
    RTT_ALPHA,
    RTT_BETA
)


# Packet flags
SYN_FLAG = 0x8
ACK_FLAG = 0x4
FIN_FLAG = 0x2


# Connection states
CLOSED = "CLOSED"
LISTEN = "LISTEN"
SYN_SENT = "SYN_SENT"
SYN_RCVD = "SYN_RCVD"
ESTABLISHED = "ESTABLISHED"
FIN_WAIT_1 = "FIN_WAIT_1"
FIN_WAIT_2 = "FIN_WAIT_2"
CLOSING = "CLOSING"
CLOSE_WAIT = "CLOSE_WAIT"
LAST_ACK = "LAST_ACK"
TIME_WAIT = "TIME_WAIT"


# Congestion-control states
SLOW_START = "SLOW_START"
CONGESTION_AVOIDANCE = "CONGESTION_AVOIDANCE"
FAST_RECOVERY = "FAST_RECOVERY"


EXIT_SUCCESS = 0
EXIT_ERROR = 1


class Packet:
    HEADER_FORMAT = PACKET_HEADER_FORMAT
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, seq=0, ack=0, flags=0, payload=b"", advertised_window=0):
        # Store the fields that make up one transport packet
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("Packet payload must be a bytes-like object")

        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = bytes(payload)
        self.advertised_window = advertised_window

    def encode(self):
        # Encode the packet header and payload into bytes
        if len(self.payload) > MSS:
            raise ValueError(f"Payload length {len(self.payload)} exceeds MSS of {MSS}")

        if not 0 <= self.advertised_window <= MAX_NETWORK_BUFFER:
            raise ValueError("Advertised window is outside the supported range")

        header = struct.pack(
            self.HEADER_FORMAT,
            self.seq,
            self.ack,
            self.flags,
            len(self.payload),
            self.advertised_window
        )

        return header + self.payload

    @staticmethod
    def decode(data):
        # Decode raw bytes into a Packet object
        if len(data) < Packet.HEADER_SIZE:
            raise ValueError("Packet too short to contain a valid header")

        seq, ack, flags, payload_len, advertised_window = struct.unpack(
            Packet.HEADER_FORMAT,
            data[:Packet.HEADER_SIZE]
        )

        if payload_len > MSS:
            raise ValueError(f"Payload length {payload_len} exceeds MSS of {MSS}")

        expected_size = Packet.HEADER_SIZE + payload_len

        if len(data) != expected_size:
            raise ValueError(
                f"Packet length mismatch: expected {expected_size} bytes, got {len(data)}"
            )

        payload = data[Packet.HEADER_SIZE:]

        return Packet(
            seq=seq,
            ack=ack,
            flags=flags,
            payload=payload,
            advertised_window=advertised_window
        )

    def __str__(self):
        # Return a readable representation for debugging
        return (
            f"Packet(seq={self.seq}, ack={self.ack}, flags={bin(self.flags)}, "
            f"payload_len={len(self.payload)}, "
            f"advertised_window={self.advertised_window})"
        )


class TransportSocket:
    def __init__(self, debug=False):
        # Initialize one single-peer reliable transport endpoint
        self.sock_fd = None
        self.conn = None
        self.my_port = None
        self.state = CLOSED
        self.debug = debug

        # RTT estimation
        self.alpha = RTT_ALPHA
        self.beta = RTT_BETA
        self.estimated_rtt = DEFAULT_TIMEOUT
        self.dev_rtt = 0.0
        self.timeout_interval = DEFAULT_TIMEOUT
        self.rtt_initialized = False

        # Sender state
        self.peer_adv_window = MAX_NETWORK_BUFFER
        self.unacked = []
        self.send_base = 0
        self.send_next = 0

        # Receiver state
        self.recv_next = 0
        self.recv_buffer = bytearray()
        self.ooo_buffer = {}
        self.pending_fin_seq = None

        # Handshake retransmission state
        self.synack_packet = None
        self.synack_sent_at = None
        self.synack_retries = 0

        # Connection teardown state
        self.fin_packet = None

        # Congestion control
        self.dup_ack_count = 0
        self.cwnd = WINDOW_INITIAL_WINDOW_SIZE
        self.ssthresh = WINDOW_INITIAL_SSTHRESH
        self.cc_state = SLOW_START

        # Synchronization
        self.recv_lock = threading.RLock()
        self.send_lock = threading.RLock()
        self.app_send_lock = threading.Lock()
        self.wait_cond = threading.Condition(self.recv_lock)
        self.stop_event = threading.Event()
        self.thread = None

    def _log(self, message):
        # Print a diagnostic message only when debug mode is enabled
        if self.debug:
            print(message)

    def _set_state(self, new_state):
        # Change the connection state
        old_state = self.state
        self.state = new_state
        self._log(f"State change: {old_state} -> {new_state}")

    def _reset_connection_state(self):
        # Reset per-connection state so this object can be reused after closing
        self.conn = None
        self.my_port = None
        self.state = CLOSED

        self.estimated_rtt = DEFAULT_TIMEOUT
        self.dev_rtt = 0.0
        self.timeout_interval = DEFAULT_TIMEOUT
        self.rtt_initialized = False

        self.peer_adv_window = MAX_NETWORK_BUFFER
        self.unacked.clear()
        self.send_base = 0
        self.send_next = 0

        self.recv_next = 0
        self.recv_buffer.clear()
        self.ooo_buffer.clear()
        self.pending_fin_seq = None

        self.synack_packet = None
        self.synack_sent_at = None
        self.synack_retries = 0
        self.fin_packet = None

        self.dup_ack_count = 0
        self.cwnd = WINDOW_INITIAL_WINDOW_SIZE
        self.ssthresh = WINDOW_INITIAL_SSTHRESH
        self.cc_state = SLOW_START

    def _open_socket(self, mode, port, server_ip=None):
        # Create the UDP socket and start the transport backend
        if mode not in ["INITIATOR", "LISTENER"]:
            return EXIT_ERROR

        if mode == "INITIATOR" and server_ip is None:
            return EXIT_ERROR

        if self.sock_fd is not None:
            return EXIT_ERROR

        self._reset_connection_state()
        self.stop_event.clear()

        try:
            self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            if mode == "INITIATOR":
                self.conn = (server_ip, port)
                self.sock_fd.bind(("", 0))
                self._set_state(SYN_SENT)
            else:
                self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock_fd.bind(("", port))
                self._set_state(LISTEN)

            self.sock_fd.settimeout(HANDSHAKE_RETRY_INTERVAL)
            self.my_port = self.sock_fd.getsockname()[1]

            self.thread = threading.Thread(target=self._backend, daemon=True)
            self.thread.start()

            if mode == "INITIATOR":
                self._send_syn()
                retries = 0

                with self.wait_cond:
                    while self.state != ESTABLISHED:
                        self.wait_cond.wait(timeout=HANDSHAKE_RETRY_INTERVAL)

                        if self.state == ESTABLISHED:
                            break

                        if self.state != SYN_SENT:
                            break

                        if retries >= MAX_HANDSHAKE_RETRIES:
                            break

                        self._send_syn()
                        retries += 1

                if self.state != ESTABLISHED:
                    self._abort_socket()
                    return EXIT_ERROR

            return EXIT_SUCCESS

        except OSError:
            self._abort_socket()
            return EXIT_ERROR

    def connect(self, server_ip, port):
        # Connect this transport socket to a remote endpoint
        result = self._open_socket("INITIATOR", port, server_ip)

        if result != EXIT_SUCCESS:
            raise ConnectionError(f"Could not connect to {server_ip}:{port}")

    def listen(self, port):
        # Bind this transport socket and listen for one incoming peer
        result = self._open_socket("LISTENER", port)

        if result != EXIT_SUCCESS:
            raise OSError(f"Could not listen on port {port}")

    def _abort_socket(self):
        # Immediately stop the backend and release the underlying UDP socket
        self.stop_event.set()

        with self.wait_cond:
            self.wait_cond.notify_all()

        if self.sock_fd is not None:
            try:
                self.sock_fd.close()
            except OSError:
                pass

        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=2.0)

        self.sock_fd = None
        self.thread = None
        self.conn = None
        self.my_port = None
        self.fin_packet = None
        self.synack_packet = None
        self.synack_sent_at = None
        self.synack_retries = 0
        self._set_state(CLOSED)

    def close(self):
        # Gracefully close the transport connection and release resources
        if self.sock_fd is None:
            return EXIT_SUCCESS

        result = EXIT_SUCCESS

        with self.app_send_lock:
            deadline = time.monotonic() + MAX_CLOSE_DURATION

            if self.state == ESTABLISHED:
                self._set_state(FIN_WAIT_1)
                self._send_fin()

                retries = 0
                last_send = time.monotonic()

                with self.wait_cond:
                    while self.state in [FIN_WAIT_1, FIN_WAIT_2, CLOSING]:
                        now = time.monotonic()

                        if now >= deadline:
                            result = EXIT_ERROR
                            break

                        if self.state in [FIN_WAIT_1, CLOSING] and now - last_send >= self.timeout_interval:
                            if retries >= MAX_FIN_RETRIES:
                                result = EXIT_ERROR
                                break

                            self._send_fin()
                            retries += 1
                            last_send = now

                        self.wait_cond.wait(timeout=0.1)

                if self.state == TIME_WAIT:
                    time.sleep(TIME_WAIT_DURATION)
                    self._set_state(CLOSED)
                elif self.state != CLOSED:
                    self._set_state(CLOSED)

            elif self.state == CLOSE_WAIT:
                self._set_state(LAST_ACK)
                self._send_fin()
                

                retries = 0
                last_send = time.monotonic()

                with self.wait_cond:
                    while self.state == LAST_ACK:
                        now = time.monotonic()

                        if now >= deadline:
                            result = EXIT_ERROR
                            break

                        if now - last_send >= self.timeout_interval:
                            if retries >= MAX_FIN_RETRIES:
                                result = EXIT_ERROR
                                break

                            self._send_fin()
                            retries += 1
                            last_send = now

                        self.wait_cond.wait(timeout=0.1)

                if self.state != CLOSED:
                    self._set_state(CLOSED)

            elif self.state != CLOSED:
                self._set_state(CLOSED)

        self.stop_event.set()

        with self.wait_cond:
            self.wait_cond.notify_all()

        if self.sock_fd is not None:
            try:
                self.sock_fd.close()
            except OSError:
                pass
            self.sock_fd = None

        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=2.0)

        self.thread = None
        self.fin_packet = None
        self.synack_packet = None
        self.synack_sent_at = None

        return result

    def send(self, data):
        # Reliably transmit application data using the current send window
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("send() requires a bytes-like object")

        data = bytes(data)

        if not data:
            return 0

        with self.app_send_lock:
            if self.state not in [ESTABLISHED, CLOSE_WAIT]:
                raise RuntimeError(f"Cannot send data in state {self.state}")

            offset = 0
            total_len = len(data)

            while offset < total_len or self.unacked:
                if self.state not in [ESTABLISHED, CLOSE_WAIT]:
                    raise ConnectionError("Connection closed before all data was acknowledged")

                with self.send_lock:
                    while offset < total_len:
                        in_flight = self._in_flight_bytes()
                        allowed_window = min(self.cwnd, self.peer_adv_window)
                        available_window = max(0, int(allowed_window - in_flight))

                        if available_window <= 0:
                            break

                        payload_len = min(MSS, available_window, total_len - offset)
                        chunk = data[offset:offset + payload_len]

                        packet = Packet(
                            seq=self.send_next,
                            ack=self.recv_next,
                            flags=ACK_FLAG,
                            payload=chunk,
                            advertised_window=self._advertised_window()
                        )

                        self.sock_fd.sendto(packet.encode(), self.conn)

                        self.unacked.append({
                            "packet": packet,
                            "sent_at": time.monotonic(),
                            "retransmitted": False,
                            "retries": 0
                        })

                        self.send_next += payload_len
                        offset += payload_len

                retry_limit_reached = False

                with self.send_lock:
                    now = time.monotonic()
                    timed_out_entries = [
                        entry for entry in self.unacked
                        if now - entry["sent_at"] >= self.timeout_interval
                    ]

                    if timed_out_entries:
                        if any(entry["retries"] >= MAX_DATA_RETRIES for entry in timed_out_entries):
                            retry_limit_reached = True
                        else:
                            self._handle_timeout()

                            for entry in timed_out_entries:
                                self.sock_fd.sendto(entry["packet"].encode(), self.conn)
                                entry["sent_at"] = now
                                entry["retransmitted"] = True
                                entry["retries"] += 1

                if retry_limit_reached:
                    self._abort_socket()
                    raise ConnectionError("Maximum data retransmissions reached")

                with self.wait_cond:
                    self.wait_cond.wait(timeout=0.05)

            return total_len

    def recv(self, length):
        # Return up to length bytes, blocking until data or EOF is available
        if length <= 0:
            raise ValueError("recv() length must be greater than 0")

        with self.wait_cond:
            while not self.recv_buffer:
                if self.state in [CLOSED, CLOSING, TIME_WAIT, LAST_ACK, CLOSE_WAIT]:
                    return b""

                self.wait_cond.wait(timeout=0.05)

            read_len = min(len(self.recv_buffer), length)
            data = bytes(self.recv_buffer[:read_len])
            del self.recv_buffer[:read_len]

            should_update_window = (
                self.conn is not None
                and self.state in [ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT]
            )

            if should_update_window:
                self._send_ack(self.recv_next)

            self.wait_cond.notify_all()
            return data

    def _advertised_window(self):
        # Return the amount of free space remaining across all receive buffers
        with self.recv_lock:
            buffered_ooo_bytes = sum(
                len(entry["data"]) for entry in self.ooo_buffer.values()
            )

            used_space = len(self.recv_buffer) + buffered_ooo_bytes
            return max(0, MAX_NETWORK_BUFFER - used_space)

    def _send_syn(self):
        # Send a SYN packet to initiate the connection handshake
        packet = Packet(
            seq=self.send_next,
            ack=0,
            flags=SYN_FLAG,
            payload=b"",
            advertised_window=self._advertised_window()
        )

        self.sock_fd.sendto(packet.encode(), self.conn)

    def _send_ack(self, ack_num):
        # Send a cumulative acknowledgment
        packet = Packet(
            seq=self.send_next,
            ack=ack_num,
            flags=ACK_FLAG,
            payload=b"",
            advertised_window=self._advertised_window()
        )

        self.sock_fd.sendto(packet.encode(), self.conn)

    def _send_syn_ack(self, client_seq, retransmission=False):
        # Send or retransmit the listener's SYN-ACK packet
        if self.synack_packet is None:
            self.synack_packet = Packet(
                seq=self.send_next,
                ack=client_seq + 1,
                flags=SYN_FLAG | ACK_FLAG,
                payload=b"",
                advertised_window=self._advertised_window()
            )

        self.sock_fd.sendto(self.synack_packet.encode(), self.conn)
        self.synack_sent_at = time.monotonic()

        if retransmission:
            self.synack_retries += 1

    def _send_fin(self):
        # Create the FIN once, then reuse it for retransmissions
        if self.fin_packet is None:
            self.fin_packet = Packet(
                seq=self.send_next,
                ack=self.recv_next,
                flags=FIN_FLAG | ACK_FLAG,
                payload=b"",
                advertised_window=self._advertised_window()
            )

            self.send_next += 1

        self.sock_fd.sendto(self.fin_packet.encode(), self.conn)

    def _update_rtt(self, sample_rtt):
        # Update the smoothed RTT estimate and retransmission timeout
        if sample_rtt <= 0:
            return

        if not self.rtt_initialized:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
            self.rtt_initialized = True
        else:
            self.dev_rtt = (
                (1 - self.beta) * self.dev_rtt
                + self.beta * abs(sample_rtt - self.estimated_rtt)
            )

            self.estimated_rtt = (
                (1 - self.alpha) * self.estimated_rtt
                + self.alpha * sample_rtt
            )

        self.timeout_interval = min(
            MAX_RTO,
            max(MIN_RTO, self.estimated_rtt + 4 * self.dev_rtt)
        )

        self._log(
            f"RTT update: sample={sample_rtt * 1000:.3f}ms "
            f"estimated={self.estimated_rtt * 1000:.3f}ms "
            f"timeout={self.timeout_interval * 1000:.3f}ms"
        )

    def _backend(self):
        # Receive packets and drive the transport state machine
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock_fd.recvfrom(Packet.HEADER_SIZE + MSS)

                try:
                    packet = Packet.decode(data)
                except ValueError:
                    continue

                if self.conn is not None and addr != self.conn:
                    continue

                if self.conn is None:
                    if self.state == LISTEN and (packet.flags & SYN_FLAG):
                        self.conn = addr
                    else:
                        continue

                previous_peer_window = self.peer_adv_window
                self.peer_adv_window = packet.advertised_window

                if self.state == LISTEN and (packet.flags & SYN_FLAG):
                    self.recv_next = packet.seq + 1
                    self.send_next = 0
                    self.send_base = 0
                    self.synack_packet = None
                    self.synack_retries = 0
                    self._send_syn_ack(packet.seq)
                    self._set_state(SYN_RCVD)
                    continue

                if self.state == SYN_RCVD and (packet.flags & SYN_FLAG):
                    self.recv_next = packet.seq + 1
                    self._send_syn_ack(packet.seq, retransmission=True)
                    continue

                if self.state == SYN_RCVD and (packet.flags & ACK_FLAG):
                    expected_ack = self.send_next + 1

                    if packet.ack != expected_ack or packet.seq != self.recv_next:
                        continue

                    self.send_next = packet.ack
                    self.send_base = packet.ack
                    self.synack_packet = None
                    self.synack_sent_at = None
                    self.synack_retries = 0
                    self._set_state(ESTABLISHED)

                    with self.wait_cond:
                        self.wait_cond.notify_all()

                    if not packet.payload and not (packet.flags & FIN_FLAG):
                        continue

                if self.state == SYN_SENT and (packet.flags & (SYN_FLAG | ACK_FLAG)) == (SYN_FLAG | ACK_FLAG):
                    expected_ack = self.send_next + 1

                    if packet.ack != expected_ack:
                        continue

                    self.send_next = packet.ack
                    self.send_base = packet.ack
                    self.recv_next = packet.seq + 1
                    self._send_ack(self.recv_next)
                    self._set_state(ESTABLISHED)

                    with self.wait_cond:
                        self.wait_cond.notify_all()

                    continue

                if self.state == ESTABLISHED and (packet.flags & (SYN_FLAG | ACK_FLAG)) == (SYN_FLAG | ACK_FLAG):
                    self._send_ack(self.recv_next)
                    continue

                if self.state in [ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT] and packet.payload:
                    with self.recv_lock:
                        if packet.seq == self.recv_next:
                            available_space = self._advertised_window()

                            if len(packet.payload) <= available_space:
                                self.recv_buffer.extend(packet.payload)
                                self.recv_next += len(packet.payload)

                                while self.recv_next in self.ooo_buffer:
                                    entry = self.ooo_buffer.pop(self.recv_next)
                                    self.recv_buffer.extend(entry["data"])
                                    self.recv_next = entry["end"]

                                if self.pending_fin_seq == self.recv_next:
                                    self._process_fin(self.pending_fin_seq)
                                else:
                                    self._send_ack(self.recv_next)

                                with self.wait_cond:
                                    self.wait_cond.notify_all()
                            else:
                                self._send_ack(self.recv_next)

                        elif packet.seq > self.recv_next:
                            buffered_ooo_bytes = sum(
                                len(entry["data"]) for entry in self.ooo_buffer.values()
                            )

                            available_space = (
                                MAX_NETWORK_BUFFER
                                - len(self.recv_buffer)
                                - buffered_ooo_bytes
                            )

                            if (
                                len(packet.payload) <= available_space
                                and packet.seq not in self.ooo_buffer
                            ):
                                self.ooo_buffer[packet.seq] = {
                                    "data": packet.payload,
                                    "end": packet.seq + len(packet.payload)
                                }

                            self._send_ack(self.recv_next)

                        else:
                            self._send_ack(self.recv_next)

                if (packet.flags & ACK_FLAG) and self.state in [
                    ESTABLISHED,
                    FIN_WAIT_1,
                    FIN_WAIT_2,
                    CLOSING,
                    CLOSE_WAIT,
                    LAST_ACK,
                    TIME_WAIT
                ]:
                    with self.send_lock:
                        if packet.ack > self.send_next:
                            continue

                        fin_acknowledged = (
                            self.fin_packet is not None
                            and packet.ack >= self.fin_packet.seq + 1
                        )

                        data_ack = packet.ack

                        if self.fin_packet is not None:
                            data_ack = min(data_ack, self.fin_packet.seq)

                        if data_ack > self.send_base:
                            acked_bytes = data_ack - self.send_base

                            newly_acked = [
                                entry for entry in self.unacked
                                if entry["packet"].seq + len(entry["packet"].payload) <= data_ack
                            ]

                            if newly_acked and not any(
                                entry["retransmitted"] for entry in newly_acked
                            ):
                                sample_entry = newly_acked[-1]
                                sample_rtt = time.monotonic() - sample_entry["sent_at"]
                                self._update_rtt(sample_rtt)

                            self.send_base = data_ack

                            self.unacked = [
                                entry for entry in self.unacked
                                if entry["packet"].seq + len(entry["packet"].payload) > data_ack
                            ]

                            self._handle_new_ack(acked_bytes)

                        elif (
                            packet.ack == self.send_base
                            and self.unacked
                            and packet.advertised_window == previous_peer_window
                            and not packet.payload
                            and not (packet.flags & (SYN_FLAG | FIN_FLAG))
                        ):
                            self._handle_duplicate_ack()

                        if fin_acknowledged:
                            fin_end = self.fin_packet.seq + 1
                            self.send_base = max(self.send_base, fin_end)
                            self.fin_packet = None

                            if self.state == FIN_WAIT_1:
                                self._set_state(FIN_WAIT_2)
                            elif self.state == CLOSING:
                                self._set_state(TIME_WAIT)
                            elif self.state == LAST_ACK:
                                self._set_state(CLOSED)

                        with self.wait_cond:
                            self.wait_cond.notify_all()

                if packet.flags & FIN_FLAG:
                    if packet.seq == self.recv_next:
                        self._process_fin(packet.seq)
                    elif packet.seq > self.recv_next:
                        self.pending_fin_seq = packet.seq
                        self._send_ack(self.recv_next)
                    else:
                        self._send_ack(self.recv_next)

                    with self.wait_cond:
                        self.wait_cond.notify_all()

            except socket.timeout:
                self._handle_backend_timeout()
                continue

            except (ConnectionResetError, OSError):
                if self.stop_event.is_set():
                    break
                raise

            except Exception as exc:
                if not self.stop_event.is_set():
                    self._log(f"Fatal backend error: {exc}")
                    self._abort_socket()

                break

    def _handle_backend_timeout(self):
        # Retransmit an unanswered SYN-ACK or reset the listener after retry exhaustion
        if self.state != SYN_RCVD or self.synack_packet is None:
            return

        now = time.monotonic()

        if self.synack_sent_at is None or now - self.synack_sent_at < HANDSHAKE_RETRY_INTERVAL:
            return

        if self.synack_retries >= MAX_HANDSHAKE_RETRIES:
            self.conn = None
            self.recv_next = 0
            self.send_base = 0
            self.send_next = 0
            self.synack_packet = None
            self.synack_sent_at = None
            self.synack_retries = 0
            self._set_state(LISTEN)
            return

        self.sock_fd.sendto(self.synack_packet.encode(), self.conn)
        self.synack_sent_at = now
        self.synack_retries += 1

    def _handle_timeout(self):
        # Respond to a retransmission timeout using Reno-style congestion control
        flight_size = self._in_flight_bytes()
        self.ssthresh = max(int(flight_size / 2), 2 * MSS)
        self.cwnd = MSS
        self.cc_state = SLOW_START
        self.dup_ack_count = 0

        self.timeout_interval = min(
            MAX_RTO,
            max(MIN_RTO, self.timeout_interval * 2)
        )

    def _handle_new_ack(self, acked_bytes):
        # Update the congestion window after receiving a new ACK
        if self.cc_state == FAST_RECOVERY:
            self.cwnd = self.ssthresh
            self.cc_state = CONGESTION_AVOIDANCE

        increment = min(acked_bytes, MSS)

        if self.cwnd < self.ssthresh:
            self.cwnd += increment
            self.cc_state = SLOW_START
        else:
            self.cwnd += (MSS * increment) / self.cwnd
            self.cc_state = CONGESTION_AVOIDANCE

        self.dup_ack_count = 0

    def _process_fin(self, fin_seq):
        # Process an in-order FIN and update the connection state
        if fin_seq != self.recv_next:
            return False

        self.recv_next += 1
        self.pending_fin_seq = None
        self._send_ack(self.recv_next)

        if self.state == ESTABLISHED:
            self._set_state(CLOSE_WAIT)
        elif self.state == FIN_WAIT_1:
            self._set_state(CLOSING)
        elif self.state == FIN_WAIT_2:
            self._set_state(TIME_WAIT)

        with self.wait_cond:
            self.wait_cond.notify_all()

        return True

    def _handle_duplicate_ack(self):
        # Handle duplicate ACKs using Reno fast retransmit and fast recovery
        self.dup_ack_count += 1

        if self.dup_ack_count == DUPLICATE_ACK_THRESHOLD:
            flight_size = self._in_flight_bytes()
            self.ssthresh = max(int(flight_size / 2), 2 * MSS)
            self.cwnd = self.ssthresh + 3 * MSS
            self.cc_state = FAST_RECOVERY

            if self.unacked:
                entry = self.unacked[0]
                self.sock_fd.sendto(entry["packet"].encode(), self.conn)
                entry["sent_at"] = time.monotonic()
                entry["retransmitted"] = True
                entry["retries"] += 1

        elif self.cc_state == FAST_RECOVERY:
            self.cwnd += MSS

    def _in_flight_bytes(self):
        # Return the number of outbound payload bytes not yet acknowledged
        with self.send_lock:
            return sum(len(entry["packet"].payload) for entry in self.unacked)