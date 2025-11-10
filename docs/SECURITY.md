# OpenPGP Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.1.x   | :white_check_mark: |
| < 2.1   | :x:                |

## Reporting a Vulnerability

We take security issues in OpenPGP seriously. If you discover a security vulnerability, we appreciate your efforts to disclose it to us responsibly.

### How to Report a Security Issue

Please report security vulnerabilities by email to:

- **Email:** [Nsfr750](mailto:nsfr750@yandex.com)
- **PGP Key:** [Nsfr750](https://keys.openpgp.org/vks/validate?email=nsfr750@yandex.com)

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

### What to Include in Your Report

When reporting a vulnerability, please include:

1. A detailed description of the vulnerability
2. Steps to reproduce the issue
3. The version(s) of OpenPGP affected
4. Any potential impact of the vulnerability
5. Your contact information (optional)

### Our Commitment

- We will acknowledge receipt of your report within 48 hours
- We will keep you informed about the progress of the vulnerability review
- We will notify you when the vulnerability has been fixed
- We will credit you in our security advisories (unless you prefer to remain anonymous)

## Security Features

### Encryption

- **Symmetric Encryption:** AES-256, AES-192, AES-128
- **Asymmetric Encryption:** RSA (up to 4096-bit), ECC (NIST P-256, P-384, P-521, Curve25519)
- **Key Exchange:** ECDH, RSA
- **Hashing:** SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512
- **Message Authentication:** HMAC-SHA256, HMAC-SHA512

### Key Management

- Secure key generation using system entropy sources
- Hardware Security Module (HSM) support
- Key revocation and expiration
- Secure key backup and recovery

### Secure File Operations

- Secure file encryption/decryption
- Secure file deletion (DoD 5220.22-M compliant)
- File integrity verification
- Secure temporary file handling

## Best Practices

### For Users

1. Always verify the authenticity of downloaded software using provided checksums and signatures
2. Use strong, unique passphrases for private keys
3. Store private keys in secure locations (e.g., hardware tokens, encrypted storage)
4. Regularly back up your keys and revocation certificates
5. Keep your OpenPGP software up to date

### For Developers

1. Follow secure coding practices
2. Use the latest stable versions of all dependencies
3. Regularly audit the codebase for security issues
4. Implement proper error handling to avoid information leakage
5. Use constant-time comparison functions for security-sensitive operations

## Security Audits

### Third-Party Audits

- [List any completed security audits]
- [Links to audit reports]

### Self-Audit Process

1. **Code Review:** All code changes are reviewed by at least one other developer
2. **Static Analysis:** Regular static code analysis using [list tools]
3. **Dependency Scanning:** Regular scanning for vulnerable dependencies
4. **Penetration Testing:** Regular security testing by internal and external teams

## Known Security Issues

| Issue | Affected Versions | Fixed In | CVE |
|-------|-------------------|----------|-----|
| [Brief description] | [Versions] | [Version] | [CVE-YYYY-XXXX] |

## Security Updates

Security updates are released as soon as possible after vulnerabilities are discovered and patched. We recommend always running the latest stable version of OpenPGP.

## Responsible Disclosure Timeline

- **2025-11-10**: Initial security policy published
- [Add future security-related events here]

## License

This security policy is licensed under the [GPLv3](LICENSE) license.
