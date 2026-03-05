# SecureCorp PKI Login System

A PKI-based secure authentication system built for ST6051CEM Practical Cryptography.

## Features
- Certificate-based login (no passwords) using X.509 / PKCS#12
- RSA-4096 Root CA + RSA-2048 user certificates
- Challenge-response authentication (anti-replay)
- Digital document signing (RSA-PSS / SHA-256)
- Hybrid message encryption (RSA-OAEP + AES-256-GCM)
- Certificate revocation (CRL)
- Full audit logging

## Installation

```bash
pip install flask cryptography
python app.py
```

Then open http://localhost:5000

## Default Admin
- Username: admin
- P12 file: admin_certificate.p12 (auto-generated on first run)
- Password: Admin@1234

## Use Cases
1. Secure employee login without passwords
2. Document signing and non-repudiation
3. Encrypted inter-department messaging
# securecorp-pki-login-system-practical-crytograpy.py
# securecorp-pki-login-system-practical-crytograpy.py
# securecorp-pki-login-system-practical-crytograpy.py
