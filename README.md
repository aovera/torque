Torque

Torque is a terminal-based, peer-to-peer (P2P) messaging application written in Rust. It utilizes an asynchronous architecture to provide end-to-end encrypted (E2E) communication with integrated support for Post-Quantum Cryptography (PQC).

DISCLOSURE & WARNING: This project is a Proof-of-Concept (PoC) developed in a high-intensity sprint. It has not undergone a formal security audit. Do not use Torque for sensitive communications where life or liberty depends on its security until the roadmap milestones (specifically PQC signatures and OOB verification) are completed.



Philosophy and Architecture

Torque is designed for high-privacy environments where "Network Silence" is a feature, not a bug. It rejects the social-media-centric model of "User Discovery."

No Discovery (Privacy by Isolation): There is no central directory or DHT. You must exchange .onion addresses through a secure, out-of-band channel.

Tor-Native: All traffic is routed through the Tor network. This masks metadata and provides a baseline layer of anonymity via Onion services.

Local Vault: Identity keys are stored in a local vault encrypted with AES-256-GCM, utilizing a key derived via Argon2. Chat history is secured in an encrypted SQLite database via SQLCipher.


Cryptographic Specification

The current implementation is specifically hardened against Harvest Now, Decrypt Later (HNDL) attacks by utilizing a hybrid key encapsulation mechanism.

1. Hybrid Key Exchange (KEM)

To protect against both classical and quantum adversaries, Torque combines:

    X25519 (Elliptic Curve Diffie-Hellman)

    Kyber768 (Lattice-based KEM)

The session key is derived using HKDF-SHA256:
Ksession​=HKDF(Salt=None,IKM=Ex25519​∥EKyber​∥Sx2519​∥SKyber​)


2. Message Encryption

Once a session is established, messages are encrypted using AES-256-GCM with unique nonces.

Roadmap & Security Hardening

As an early-stage project, the following features are prioritized to transform the PoC into a robust security tool:

    [ ] Post-Quantum Signatures (ML-DSA / Dilithium): Integrating Dilithium3 to sign handshake packets, preventing future quantum adversaries from performing MitM attacks by spoofing Onion identities.

    [ ] Out-of-Band (OOB) Fingerprinting: Implementing a terminal UI to display cryptographic fingerprints (SHA256 of all public keys) for manual verification.

    [ ] Network Sanitization: - Implementing Length Sanitization to prevent memory exhaustion (DoS) attacks.

        Implementing Network Padding to ensure all packets are of uniform size, mitigating traffic analysis.

    [ ] Reliable Messaging: Completing the retry logic for pending messages using exponential backoff.

    [ ] Terminal UI (TUI): Transitioning to a professional interface using ratatui.

🚀 Getting Started
Prerequisites

    Rust (Latest Stable)

    Tor Daemon (Configured on 127.0.0.1:9050)

    Development headers for SQLCipher and OpenSSL (libssl-dev, build-essential on Linux).

Build from Source

```git clone https://github.com/aovera/torque```

```cd torque```

```cargo build --release```


Security Posture

Torque currently relies on Tor Client Authentication and the computational hardness of the Birthday Attack on Tor v3 addresses for its primary identity verification. While this provides significant protection today, it is theoretically vulnerable to active quantum adversaries. Users should treat all "unverified" fingerprints with skepticism.


Important Warning

Help page or usage instructions is deliberately not added to discourage full use until project reach a mature state. But if you still insist to use, you are free to discover them in source code.




#USE TOR CLIENT AUTHORIZATION
