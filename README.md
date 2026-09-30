# Reliable Transport Protocol over UDP

This project implements a TCP-inspired reliable transport protocol in Python using UDP sockets.

I originally built the project for a computer networks course, then expanded it with additional reliability features, congestion control, flow control, and automated testing.

The protocol provides reliable ordered delivery even though UDP itself does not guarantee delivery, ordering, or retransmission.

## Features

- Three-way connection handshake
- Reliable ordered byte-stream delivery
- Sequence numbers and cumulative ACKs
- Sliding-window transmission
- Receiver-advertised flow control
- Out-of-order packet buffering
- Timeout-based retransmission
- Adaptive RTT and retransmission timeout estimation
- Reno-style congestion control
  - Slow start
  - Congestion avoidance
  - Fast retransmit
  - Fast recovery
- FIN-based connection teardown
- Handshake and FIN retransmission
- Malformed packet handling
- Optional debug output

## Project Files

- `transport.py` - Main transport protocol implementation
- `config.py` - Protocol constants and configuration
- `client.py` - File-transfer client
- `server.py` - File-transfer server
- `test_suite.py` - Automated integration tests
- `sample_data.txt` - Sample file used by the demo

## File Transfer Demo

The project uses only the Python standard library.

Open two terminals in the project directory.

Start the server first:

```bash
python server.py
```

Then start the client:

```bash
python client.py
```

By default, the client sends `sample_data.txt` to the server using the custom reliable transport protocol.

The server saves the received file to:

`received_files/sample_data.txt`

Both sides print the SHA-256 hash of the transferred file so the file's integrity can be verified.

You can also send a different file:

```bash
python client.py path/to/file.txt
```

## Automated Tests

Run the integration test suite with:

```bash
python test_suite.py
```

The suite tests:

1. Clean 100 KB bidirectional transfer
2. Timeout retransmission
3. Middle-packet loss and fast retransmit
4. Handshake loss recovery
5. Zero-window flow-control recovery
6. FIN loss and teardown recovery
7. Malformed packet handling

Current result:

```text
Reliable Transport Protocol Test Suite
==================================================
[1/7] Clean 100 KB bidirectional transfer ... PASS
[2/7] Timeout retransmission ... PASS
      Dropped: data packet seq=1, payload=1382
[3/7] Middle-packet loss / fast retransmit ... PASS
      Dropped: middle data packet seq=26259, payload=1382
[4/7] Handshake loss recovery ... PASS
      Dropped: first SYN
[5/7] Zero-window flow-control recovery ... PASS
[6/7] FIN loss / teardown recovery ... PASS
      Dropped: first FIN
[7/7] Malformed packet handling ... PASS
==================================================
7/7 tests passed
All transport integration tests passed.
```

The packet-loss tests use a UDP proxy inside the test suite that intentionally drops selected packets before they reach the receiver.

Large transfers are verified using SHA-256 hashes to confirm that the received data exactly matches the data that was sent.

## Limitations

This project focuses on core reliable transport behavior rather than implementing every feature of TCP.

Current limitations include:

- One peer per `TransportSocket`
- No multi-client `accept()` interface
- No selective acknowledgments
- No sequence-number wraparound handling
- No dedicated persist timer for a lost zero-window update