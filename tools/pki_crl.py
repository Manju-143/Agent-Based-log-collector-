from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_bytes(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def load_ca(ca_dir: str):
    ca_key = load_pem_private_key(read_bytes(os.path.join(ca_dir, "ca_key.pem")), password=None)
    ca_cert = x509.load_pem_x509_certificate(read_bytes(os.path.join(ca_dir, "ca_cert.pem")))
    return ca_key, ca_cert


def load_crl(path: str) -> x509.CertificateRevocationList | None:
    if not os.path.exists(path):
        return None
    data = read_bytes(path)
    if not data.strip():
        return None
    return x509.load_pem_x509_crl(data)


def build_crl(ca_key, ca_cert, revoked_serials: set[int]) -> x509.CertificateRevocationList:
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=7))
    )

    for serial in sorted(revoked_serials):
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def parse_serial(s: str) -> int:
    s = s.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    return int(s)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--revoke-serial", action="append", default=[], help="Serial number to revoke (int or 0xHEX)")
    ap.add_argument("--ca-dir", default=os.path.join("pki", "ca"))
    args = ap.parse_args()

    ca_dir = args.ca_dir
    crl_path = os.path.join(ca_dir, "ca_crl.pem")

    ca_key, ca_cert = load_ca(ca_dir)

    revoked_serials: set[int] = set()
    existing = load_crl(crl_path)
    if existing:
        for r in existing:
            revoked_serials.add(r.serial_number)

    for s in args.revoke_serial:
        revoked_serials.add(parse_serial(s))

    crl = build_crl(ca_key, ca_cert, revoked_serials)
    write_bytes(crl_path, crl.public_bytes(serialization.Encoding.PEM))

    print(f"[ok] CRL written: {crl_path}")
    print(f"[ok] revoked serials: {sorted(revoked_serials) if revoked_serials else 'none'}")
    print("[tip] To revoke a cert, pass --revoke-serial <serial> shown when issuing certs.")


if __name__ == "__main__":
    main()