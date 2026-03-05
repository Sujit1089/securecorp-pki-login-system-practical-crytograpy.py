# SecureCorp PKI Login System
## ST6051CEM Practical Cryptography — Sujit Kafle (230378)

## Installation
```
pip install flask cryptography
python app.py
```
Open http://localhost:5001

## Default Admin Login
- File: admin_certificate.p12 (auto-generated on first run)
- Password: Admin@1234

## Project Structure
- app.py            → Flask web app (all routes & logic)
- crypto_utils.py   → All cryptographic operations (CA, certs, signatures, encryption)
- templates/        → 11 HTML templates (dark PKI-themed UI)

## Features
- PKI certificate-based login (no passwords)
- RSA-4096 Root CA + RSA-2048 user certificates (X.509v3)
- PKCS#12 encrypted keystores
- Challenge-response authentication (anti-replay)
- Digital document signing (RSA-PSS / SHA-256)
- Signature verification
- Hybrid encryption (RSA-OAEP + AES-256-GCM)
- Certificate revocation (admin panel)
- Full audit logging (SQLite)
