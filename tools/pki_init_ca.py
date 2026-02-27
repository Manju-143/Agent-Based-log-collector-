from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_pem(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def main() -> None:
    ca_dir = os.path.join("pki", "ca")
    ensure_dir(ca_dir)

    ca_key_path = os.path.join(ca_dir, "ca_key.pem")
    ca_cert_path = os.path.join(ca_dir, "ca_cert.pem")

    # Generate CA private key (ECDSA P-256)
    ca_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Secure Logging"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PKSL Local CA"),
        ]
    )

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))  # ~10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    write_pem(
        ca_key_path,
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    write_pem(ca_cert_path, cert.public_bytes(serialization.Encoding.PEM))

    # Create empty CRL file placeholder (we’ll populate in PKI-2)
    crl_path = os.path.join(ca_dir, "ca_crl.pem")
    if not os.path.exists(crl_path):
        write_pem(crl_path, b"")

    print(f"[ok] CA key:   {ca_key_path}")
    print(f"[ok] CA cert:  {ca_cert_path}")
    print(f"[ok] CA CRL:   {crl_path} (empty placeholder)")


if __name__ == "__main__":
    main()