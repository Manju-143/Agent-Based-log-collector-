from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.hashes import SHA256


@dataclass
class PKIConfig:
    ca_cert_path: str = os.path.join("pki", "ca", "ca_cert.pem")
    crl_path: str = os.path.join("pki", "ca", "ca_crl.pem")


def load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_crl(path: str) -> x509.CertificateRevocationList | None:
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        data = f.read()
    if not data.strip():
        return None
    return x509.load_pem_x509_crl(data)


def verify_issued_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    # Verify issuer name match
    if cert.issuer != ca_cert.subject:
        raise ValueError("Certificate issuer does not match CA subject")

    # Verify signature using CA public key (ECDSA in our CA)
    pub = ca_cert.public_key()
    if not isinstance(pub, EllipticCurvePublicKey):
        raise ValueError("Unsupported CA public key type")

    pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        ec.ECDSA(cert.signature_hash_algorithm),
    )


def check_not_revoked(cert: x509.Certificate, crl: x509.CertificateRevocationList | None) -> None:
    if crl is None:
        return
    for revoked in crl:
        if revoked.serial_number == cert.serial_number:
            raise ValueError("Certificate is revoked by CRL")


def validate_cert_path(cert_path: str, cfg: PKIConfig = PKIConfig()) -> x509.Certificate:
    ca = load_cert(cfg.ca_cert_path)
    cert = load_cert(cert_path)
    crl = load_crl(cfg.crl_path)

    verify_issued_by_ca(cert, ca)
    check_not_revoked(cert, crl)
    return cert