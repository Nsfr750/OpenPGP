# OpenPGP - Development Roadmap (2025-2026)

This document outlines the development roadmap for the OpenPGP application, including completed features and future plans as of November 2025.

## Version 2.2.0 (Q4 2025) - Current Release

### New Features

- **Enhanced TPM 2.0 Integration**
  - [x] Basic Windows TPM 2.0 detection
  - **Full Windows TPM 2.0 Support**
    - [ ] Windows TBS (TPM Base Services) integration
    - [ ] TPM 2.0 key storage and management
    - [ ] Secure key generation and storage in TPM
    - [ ] Key attestation and certification
    - [ ] Sealed storage for sensitive data
    - [ ] Integration with Windows Hello for Business
  - **TPM-based Operations**
    - [ ] TPM-based key generation and storage
    - [ ] Hardware-backed encryption/decryption
    - [ ] Secure key import/export
    - [ ] TPM-based authentication
  - **Remote Attestation**
    - [ ] Platform Configuration Registers (PCR) validation
    - [ ] TPM quote generation and verification
    - [ ] Integration with remote attestation services
  - **Cross-platform Support**
    - [ ] Linux TPM 2.0 support (tpm2-tss)
    - [ ] macOS Secure Enclave integration
    - [ ] Unified API for cross-platform TPM operations

- **Quantum-Resistant Cryptography**
  - [x] Research and evaluation of post-quantum algorithms
  - **Kyber Integration** (Key Encapsulation Mechanism)
    - [ ] Kyber-512/768/1024 support
    - [ ] Hardware-optimized implementations
    - [ ] Integration with existing key exchange protocols
    - [ ] Performance benchmarking and optimization
  - **Dilithium Integration** (Digital Signatures)
    - [ ] Dilithium2/3/5 support
    - [ ] Fast verification implementations
    - [ ] Integration with X.509 and OpenPGP formats
    - [ ] Side-channel attack resistance
  - **Hybrid Cryptography**
    - [ ] X25519 + Kyber hybrid key exchange
    - [ ] Ed25519 + Dilithium hybrid signatures
    - [ ] Backward compatibility modes
    - [ ] Performance optimization for hybrid operations
  - **Migration & Interoperability**
    - [ ] Algorithm transition policies
    - [ ] Dual certificate support
    - [ ] Fallback mechanisms
    - [ ] Compliance with NIST PQC standards

- **Enhanced Encryption Modes**
  - [ ] Hybrid encryption combining symmetric and asymmetric schemes
  - [ ] Support for multiple encryption backends (OpenSSL, libsodium, etc.)
  - [ ] Hardware-accelerated cryptographic operations
  - [ ] Post-quantum secure key exchange

- **Decentralized Identity**
  - DID (Decentralized Identifiers) integration
  - Verifiable Credentials support
  - Cross-platform identity management

### Improvements

- Performance optimizations for large file encryption
- Enhanced key synchronization across devices
- Improved hardware token support (YubiKey 5, Nitrokey 3)

## Version 2.3.0 (Q1 2026)

### Major Updates

- **Unified Cross-Platform Experience**
  - Complete UI/UX overhaul with Flutter-based interface
  - Native performance on all platforms
  - Seamless sync between desktop and mobile

- **Advanced Collaboration**
  - End-to-end encrypted team workspaces
  - Secure real-time document collaboration
  - Granular permission controls

- **Enterprise Suite**
  - Centralized administration console
  - Advanced audit logging and compliance reporting
  - SCIM 2.0 provisioning
  - SIEM integration

## Version 2.4.0 (Q2 2026)

### Planned Features

- **AI-Powered Security**
  - Anomaly detection in key usage
  - Smart key rotation policies
  - Automated security recommendations

- **Expanded Protocol Support**
  - MLS (Message Layer Security) protocol
  - Secure multi-party computation
  - Zero-knowledge proof integration

- **Developer Platform**
  - Plugin SDK and marketplace
  - WebAssembly runtime for extensions
  - Comprehensive API documentation

## Version 2.5.0 (Q3 2026)

### Future Vision

- **Decentralized Infrastructure**
  - Blockchain-based key management
  - Distributed storage for encrypted data
  - Smart contract-based access control

- **Privacy-Preserving Features**
  - Private set intersection
  - Homomorphic encryption support
  - Secure multi-party computation

- **Global Compliance**
  - Automated compliance with GDPR, CCPA, and other regulations
  - Data sovereignty controls
  - Cross-border data transfer management

## Release Strategy

### Versioning

- **Feature Releases**: Quarterly updates (Q1, Q2, Q3, Q4)
- **Patch Releases**: Monthly security and bug fix updates
- **LTS Releases**: Annual major versions with 3 years of security updates

### Support Policy

- **Active Development**: Current and next minor version
- **Security Support**: All versions released in the last 12 months
- **Extended Support**: Available for enterprise customers

## Contributing

We welcome contributions from the community! If you'd like to contribute to the development of OpenPGP, please see our [Contributing Guidelines](CONTRIBUTING.md).

### How to Get Involved

1. **Code Contributions**: Check our [good first issues](https://github.com/Nsfr750/OpenPGP/contribute)
2. **Documentation**: Help improve our docs and tutorials
3. **Testing**: Join our beta testing program
4. **Translation**: Help localize OpenPGP to your language

## Feature Requests

Have an idea for a new feature? Please open an issue on our [GitHub repository](https://github.com/Nsfr750/OpenPGP) with the 'enhancement' label.

## Reporting Issues

Found a bug or security vulnerability? Please report it by [creating an issue](https://github.com/Nsfr750/OpenPGP/issues/new/choose) with detailed steps to reproduce.

## Feedback

Your feedback is valuable! Please open an issue on GitHub to suggest new features or report bugs.
