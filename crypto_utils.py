import os, json, secrets
import datetime as dt
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend

# Keep datetime alias for compatibility
import datetime
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend

CA_KEY_PATH = "ca_key.pem"
CA_CERT_PATH = "ca_cert.pem"
REVOKED_SERIALS_PATH = "revoked.json"

def initialize_ca():
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        return load_ca()
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureCorp PKI Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureCorp Root CA"),
    ])
    ca_cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256(), default_backend()))
    with open(CA_KEY_PATH, "wb") as f:
        f.write(ca_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(CA_CERT_PATH, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(REVOKED_SERIALS_PATH, "w") as f:
        json.dump([], f)
    return ca_key, ca_cert

def load_ca():
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return ca_key, ca_cert

def get_ca_cert_pem():
    with open(CA_CERT_PATH, "rb") as f:
        return f.read().decode()

def generate_user_credentials(username, email, organization, p12_password):
    ca_key, ca_cert = load_ca()
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])
    serial = x509.random_serial_number()
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(serial)
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256(), default_backend()))
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=username.encode(), key=user_key, cert=cert, cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(p12_password.encode()))
    return p12_bytes, serial

def validate_certificate(cert):
    ca_key, ca_cert = load_ca()
    try:
        ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm)
    except Exception:
        return {"valid": False, "reason": "Certificate not issued by our CA."}
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    if now < not_before:
        return {"valid": False, "reason": "Certificate not yet valid."}
    if now > not_after:
        return {"valid": False, "reason": "Certificate has expired."}
    revoked = load_revoked_serials()
    if cert.serial_number in revoked:
        return {"valid": False, "reason": "Certificate has been revoked."}
    return {"valid": True, "reason": "Certificate is valid."}

def load_p12(p12_data, password):
    try:
        private_key, cert, chain = pkcs12.load_key_and_certificates(
            p12_data, password.encode(), default_backend())
        return private_key, cert
    except Exception:
        return None, None

def generate_challenge():
    return secrets.token_hex(32)

def sign_challenge(private_key, challenge):
    return private_key.sign(challenge.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

def verify_challenge_signature(cert, challenge, signature):
    try:
        cert.public_key().verify(signature, challenge.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except Exception:
        return False

def sign_message(private_key, message):
    return private_key.sign(message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

def verify_signature(cert, message, signature):
    try:
        cert.public_key().verify(signature, message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except Exception:
        return False

def encrypt_message(recipient_cert, plaintext):
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    encrypted_key = recipient_cert.public_key().encrypt(aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return {"encrypted_key": encrypted_key.hex(), "iv": iv.hex(),
            "ciphertext": ciphertext.hex(), "tag": encryptor.tag.hex()}

def decrypt_message(private_key, encrypted_data):
    aes_key = private_key.decrypt(bytes.fromhex(encrypted_data["encrypted_key"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    decryptor = Cipher(algorithms.AES(aes_key),
        modes.GCM(bytes.fromhex(encrypted_data["iv"]), bytes.fromhex(encrypted_data["tag"])),
        backend=default_backend()).decryptor()
    return decryptor.update(bytes.fromhex(encrypted_data["ciphertext"])) + decryptor.finalize()

def load_revoked_serials():
    if not os.path.exists(REVOKED_SERIALS_PATH):
        return []
    with open(REVOKED_SERIALS_PATH) as f:
        return json.load(f)

def revoke_certificate(serial_number):
    revoked = load_revoked_serials()
    if serial_number not in revoked:
        revoked.append(serial_number)
    with open(REVOKED_SERIALS_PATH, "w") as f:
        json.dump(revoked, f)

def get_cert_info(cert):
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return {
        "common_name": cn_attrs[0].value if cn_attrs else "N/A",
        "organization": org_attrs[0].value if org_attrs else "N/A",
        "serial": str(cert.serial_number),
        "not_before": cert.not_valid_before.strftime("%Y-%m-%d"),
        "not_after": cert.not_valid_after.strftime("%Y-%m-%d"),
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
    }
