# Torque

**Torque** is an asynchronous, end-to-end encrypted (E2E), and post-quantum cryptography-supported terminal-based P2P messaging application written in Rust.

Unlike traditional messaging applications, Torque does not rely on a centralized server. It keeps your local database (SQLCipher) and identity in a fully encrypted local vault, ensuring maximum privacy and security.

## ✨ Key Features

- **Post-Quantum Ready (Hybrid KEM):** Utilizes traditional **X25519** (Elliptic Curve Cryptography) alongside quantum-resistant **Kyber768** algorithms for robust key exchange.
- **End-to-End Encryption (E2E):** All network traffic is encrypted using **AES-256-GCM**. Network packets are securely serialized with `bincode`.
- **Fully Encrypted Local Storage:**
  - Your Private Keys are stored in a local Vault encrypted with **AES-256-GCM**, utilizing a 32-byte key derived via **Argon2**.
  - Your chat history, contacts, and application settings are kept in an encrypted SQLite database powered by **SQLCipher**.
- **Asynchronous Network Architecture:** Built on top of **Tokio**, Torque provides non-blocking, high-concurrency I/O operations, ensuring minimum latency and high fault tolerance in message transmission.

---

## 🔐 Cryptographic Architecture

Torque's security model is designed to meet the highest modern cryptographic standards:

1. **Identity Generation:** X25519 and Kyber768 key pairs are generated during the initial setup.
2. **Identity Protection:** The user's master password is mathematically hashed into a 32-byte key via **Argon2**, and the private keys are encrypted on disk using **AES-256-GCM**.
3. **P2P Handshake:** When clients interact, ephemeral keys are generated and mutually verified to establish a secure, symmetric Session Key.
4. **Message Transmission:** Messages are encrypted using these single-use session keys with AES-256-GCM and transmitted over TCP sockets.

---

## 🛠️ Build and Installation

### Prerequisites
- [Rust and Cargo](https://rustup.rs/) (Latest stable version recommended)
- A C compiler and necessary cryptography dependencies for SQLCipher and Argon2 (e.g., `build-essential`, `pkg-config`, `libssl-dev` on Linux).

### Compiling from Source

Clone the repository and build the project in release mode:

```bash
git clone [https://github.com/aovera/torque.git](https://github.com/aovera/torque.git)
cd torque
cargo build --release
