# IOCP Chat Server

A multi-client chat server built on Windows I/O Completion Ports (IOCP), with a from-scratch authentication stack, chunked file transfer, and offline message delivery. Written in C++20.

## Highlights

- **IOCP-native concurrency** — sustains 1,00–1,500 concurrent client connections with low CPU utilization via native IOCP dispatch. The current scaling ceiling is packet-pool exhaustion, not CPU or memory contention.
- **Custom authentication stack** (libsodium) — Argon2id password hashing, HMAC-SHA-512-256 session tokens, refresh-token rotation with reuse detection, UUID-based identity, friend codes, token-bucket rate limiting, and email OTP verification offloaded from IOCP worker threads to keep the hot path non-blocking.
- **Lock-free MPSC queue** for cross-thread message handoff between IOCP worker threads.
- **Race condition found and fixed** in the packet pool's buffer-reuse path (root cause: reuse flags weren't reset on borrow). Fix validated under sustained load — 1500 concurrent clients,  approx. 28M packets, zero delivery failures.
- **Throughput redesign** — moved from a single consumer thread to per-client queues distributed across the IOCP worker pool, removing a throughput ceiling that previously capped the server at ~900 clients.
- **Chunked file transfer** chunking the file to use maximum 4MB of memory during run time , per transfer at a time 
- **Offline message delivery** — per-receiver in-memory queue with reconnect-triggered draining and disk spillover for clients offline longer than the memory buffer can hold( currently implementing it ).

## Architecture

- `IOCPManager` dispatches I/O completion events across a fixed worker thread pool
- `Session` / `SessionManager` own per-connection state and lifecycle
- `PacketPool` / `SessionPool` reuse fixed-size buffers and session objects to avoid per-message heap allocation
- `MessageRouter` / `GroupManager` handle chat fan-out and group membership
- `AuthManager` / `SignUp` / `Login` implement the credential and token lifecycle
- `FileTransferManager` runs chunked transfers independently of the chat message path
- `ManageOffline` handles queuing and delivery for both online and disconnected  recipients

## Status

Actively developed — not a finished product. Currently in progress:
- Hardening `Packet::parseData()` against parsing edge cases (bounds/null checks on the payload boundary)
- Formalizing connection state transitions for the offline-message drain path, to prevent message reordering on reconnect

## Build

**Dependencies:** CMake ≥ 3.15, a C++20 compiler (MSVC ), zlib, libsodium (via vcpkg or MSYS2/pkg-config).

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

Produces `Server.exe` and `Client.exe`.

## Project structure

```
authentication/    # Sign-up, login, token lifecycle, credential storage
chat/              # Group membership and message routing
client/            # Client application
datastructure/     # Lock-free MPSC queue, fixed-size queue, hash table
filetransfer/      # Chunked file transfer with CRC-32 verification
network/           # IOCPManager, per-connection I/O context
offlineManager/     # Offline message queue and drain logic
pool/              # PacketPool, SessionPool, IOContextPool — fixed-size object reuse
protocol/          # Wire packet format, header, type definitions
server/            # Server entry point and top-level wiring
session/           # Per-connection session state
storage/           # User record persistence
token/             # Token and user-info types
utils/             # Logging
```

## Tech stack

C++20 · Windows IOCP · Winsock2 (`ws2_32`, `mswsock`) · libsodium · zlib · CMake
