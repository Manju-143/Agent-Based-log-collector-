from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def read_pem(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_pem(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def load_ca(ca_dir: str):
    ca_key = serialization.load_pem_private_key(read_pem(os.path.join(ca_dir, "ca_key.pem")), password=None)
    ca_cert = x509.load_pem_x509_certificate(read_pem(os.path.join(ca_dir, "ca_cert.pem")))
    return ca_key, ca_cert


def build_cert(common_name: str, ca_key, ca_cert, is_server: bool, host: str | None):
    key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Secure Logging"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=825))  # ~27 months
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    # EKU: serverAuth/clientAuth
    eku = [ExtendedKeyUsageOID.SERVER_AUTH] if is_server else [ExtendedKeyUsageOID.CLIENT_AUTH]
    builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)

    # SubjectAltName for server (DNS/IP)
    if is_server and host:
        san_items = []
        try:
            san_items.append(x509.IPAddress(ip_address(host)))
        except ValueError:
            san_items.append(x509.DNSName(host))
        builder = builder.add_extension(x509.SubjectAlternativeName(san_items), critical=False)

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return key, cert


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="Common Name, e.g. pksl-server or agent-01")
    ap.add_argument("--type", required=True, choices=["server", "agent"])
    ap.add_argument("--host", default=None, help="For server cert SAN (e.g., 127.0.0.1 or localhost)")
    args = ap.parse_args()

    ca_dir = os.path.join("pki", "ca")
    out_dir = os.path.join("pki", "issued")

    ca_key, ca_cert = load_ca(ca_dir)
    is_server = args.type == "server"

    key, cert = build_cert(args.name, ca_key, ca_cert, is_server=is_server, host=args.host)

    key_path = os.path.join(out_dir, f"{args.name}_key.pem")
    cert_path = os.path.join(out_dir, f"{args.name}_cert.pem")

    write_pem(
        key_path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    write_pem(cert_path, cert.public_bytes(serialization.Encoding.PEM))

    print(f"[ok] issued {args.type} cert")
    print(f" - key:  {key_path}")
    print(f" - cert: {cert_path}")
    print(f" - issuer: {ca_cert.subject.rfc4514_string()}")
    print(f" - serial: {cert.serial_number}")


if __name__ == "__main__":
    main()