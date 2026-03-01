import base64
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.x509.oid import NameOID


# -------------------------
# Paths / folders
# -------------------------
ROOT = Path(".")
KEYS_DIR = ROOT / "keys"
PKI_DIR = ROOT / "pki"
CA_DIR = PKI_DIR / "ca"
ISSUED_DIR = PKI_DIR / "issued"


def ensure_dirs() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    CA_DIR.mkdir(parents=True, exist_ok=True)
    ISSUED_DIR.mkdir(parents=True, exist_ok=True)


# -------------------------
# Helpers
# -------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def prompt(default: str, text: str) -> str:
    v = input(f"{text} [{default}]: ").strip()
    return v if v else default


def banner(msg: str) -> None:
    print("\n" + "=" * 70)
    print(msg)
    print("=" * 70)


# -------------------------
# AES key
# -------------------------
def generate_aes_key_b64() -> str:
    key = os.urandom(32)  # 32 bytes = AES-256
    return base64.b64encode(key).decode("ascii")


# -------------------------
# CA generation (ECDSA P-256)
# -------------------------
@dataclass
class CAArtifacts:
    ca_key_path: Path
    ca_cert_path: Path
    crl_path: Path


def ca_paths() -> CAArtifacts:
    return CAArtifacts(
        ca_key_path=CA_DIR / "ca_key.pem",
        ca_cert_path=CA_DIR / "ca_cert.pem",
        crl_path=CA_DIR / "ca_crl.pem",
    )


def create_ca(common_name: str = "PKSL-CA", years_valid: int = 5) -> None:
    ensure_dirs()
    paths = ca_paths()

    if paths.ca_key_path.exists() or paths.ca_cert_path.exists():
        print(f"[warn] CA already exists at {paths.ca_key_path} / {paths.ca_cert_path}")
        ans = input("Overwrite existing CA? (yes/no) [no]: ").strip().lower() or "no"
        if ans != "yes":
            print("[ok] keeping existing CA.")
            return

    ca_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKSL"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_utc() - timedelta(minutes=5))
        .not_valid_after(now_utc() + timedelta(days=365 * years_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=True,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    write_bytes(
        paths.ca_key_path,
        ca_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
    )
    write_bytes(paths.ca_cert_path, cert.public_bytes(Encoding.PEM))

    # Create an empty CRL initially
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(cert.subject)
        .last_update(now_utc() - timedelta(minutes=1))
        .next_update(now_utc() + timedelta(days=7))
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    write_bytes(paths.crl_path, crl.public_bytes(Encoding.PEM))

    print("[ok] CA created:")
    print(f"  - CA key:  {paths.ca_key_path}")
    print(f"  - CA cert: {paths.ca_cert_path}")
    print(f"  - CRL:     {paths.crl_path}")


def load_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    paths = ca_paths()
    if not paths.ca_key_path.exists() or not paths.ca_cert_path.exists():
        raise FileNotFoundError("CA not found. Run 'Create CA' first.")
    ca_key = serialization.load_pem_private_key(read_bytes(paths.ca_key_path), password=None)
    ca_cert = x509.load_pem_x509_certificate(read_bytes(paths.ca_cert_path))
    return ca_key, ca_cert


# -------------------------
# Agent certificate issuance (ECDSA CA signs agent cert)
# -------------------------
def issue_agent_cert(agent_id: str, days_valid: int = 365) -> Path:
    ensure_dirs()
    ca_key, ca_cert = load_ca()

    agent_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKSL"),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(agent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_utc() - timedelta(minutes=5))
        .not_valid_after(now_utc() + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                key_agreement=True,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_path = ISSUED_DIR / f"{agent_id}_cert.pem"
    key_path = ISSUED_DIR / f"{agent_id}_key.pem"  # NOTE: private key (keep secret)

    write_bytes(key_path, agent_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    write_bytes(cert_path, cert.public_bytes(Encoding.PEM))

    print("[ok] Agent cert issued:")
    print(f"  - Agent cert: {cert_path}")
    print(f"  - Agent key:  {key_path}  (DO NOT COMMIT)")

    print("[info] Agent cert serial:", cert.serial_number)
    return cert_path


def show_cert_serial(cert_path: Path) -> int:
    cert = x509.load_pem_x509_certificate(read_bytes(cert_path))
    print(f"[ok] Serial for {cert_path}: {cert.serial_number}")
    return cert.serial_number


# -------------------------
# CRL revoke
# -------------------------
def load_crl(crl_path: Path) -> x509.CertificateRevocationList | None:
    if not crl_path.exists():
        return None
    data = read_bytes(crl_path)
    if not data.strip():
        return None
    return x509.load_pem_x509_crl(data)


def write_crl(ca_key, ca_cert, revoked_serials: set[int], crl_path: Path) -> None:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now_utc() - timedelta(minutes=1))
        .next_update(now_utc() + timedelta(days=7))
    )

    for serial in sorted(revoked_serials):
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now_utc())
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    write_bytes(crl_path, crl.public_bytes(Encoding.PEM))


def revoke_by_serial(serial: int) -> None:
    ensure_dirs()
    ca_key, ca_cert = load_ca()
    paths = ca_paths()

    revoked: set[int] = set()
    existing = load_crl(paths.crl_path)
    if existing:
        for r in existing:
            revoked.add(r.serial_number)

    revoked.add(serial)
    write_crl(ca_key, ca_cert, revoked, paths.crl_path)

    print("[ok] Updated CRL:", paths.crl_path)
    print("[ok] Revoked serials:", sorted(revoked))


def revoke_by_cert_file(cert_path: Path) -> None:
    serial = show_cert_serial(cert_path)
    revoke_by_serial(serial)


# -------------------------
# Ed25519 signing keys (agent)
# -------------------------
def generate_ed25519_agent_keys(agent_id: str) -> None:
    ensure_dirs()
    priv_path = KEYS_DIR / f"{agent_id}_ed25519_private.pem"
    pub_path = KEYS_DIR / f"{agent_id}_ed25519_public.pem"

    if priv_path.exists() or pub_path.exists():
        print(f"[warn] Ed25519 keys already exist for {agent_id} in {KEYS_DIR}")
        ans = input("Overwrite? (yes/no) [no]: ").strip().lower() or "no"
        if ans != "yes":
            print("[ok] keeping existing keys.")
            return

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    write_bytes(priv_path, priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    write_bytes(pub_path, pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    print("[ok] Ed25519 signing keys generated:")
    print(f"  - Private: {priv_path}  (DO NOT COMMIT)")
    print(f"  - Public:  {pub_path}")


# -------------------------
# Noise static keys (simple raw bytes)
# -------------------------
def generate_noise_static_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        print(f"[warn] Noise key already exists: {path}")
        ans = input("Overwrite? (yes/no) [no]: ").strip().lower() or "no"
        if ans != "yes":
            print("[ok] keeping existing Noise key.")
            return
    key = os.urandom(32)  # 32 bytes for X25519 private key seed used by many libs
    write_bytes(path, key)
    print(f"[ok] Noise static private key generated: {path}  (DO NOT COMMIT)")


def generate_noise_keys(agent_id: str) -> None:
    ensure_dirs()
    # Agent Noise static private key
    agent_noise = KEYS_DIR / f"{agent_id}_noise_private.key"
    generate_noise_static_key(agent_noise)

    # Server Noise static private key
    server_noise = KEYS_DIR / "server_noise_private.key"
    generate_noise_static_key(server_noise)


# -------------------------
# Menu
# -------------------------
def menu() -> None:
    banner("PKSL Key + PKI Wizard")

    ensure_dirs()
    print("Folders used:")
    print(f"  - keys/       : {KEYS_DIR.resolve()}")
    print(f"  - pki/ca/     : {CA_DIR.resolve()}")
    print(f"  - pki/issued/ : {ISSUED_DIR.resolve()}")

    while True:
        print("\nChoose an action:")
        print("  1) Generate AES-256 key (base64)")
        print("  2) Create CA (ECDSA P-256) + empty CRL")
        print("  3) Issue agent X.509 cert (signed by CA)")
        print("  4) Show cert serial number")
        print("  5) Revoke cert by cert file (updates CRL)")
        print("  6) Generate Ed25519 signing keys (agent)")
        print("  7) Generate Noise static keys (agent + server)")
        print("  8) Do ALL for an agent (Ed25519 + Noise + agent cert)")
        print("  9) Exit")

        choice = (input("\nEnter choice [1-9]: ").strip() or "9")

        try:
            if choice == "1":
                k = generate_aes_key_b64()
                print("\n[ok] AES key (base64):")
                print(k)
                print("\nSet it like:")
                print(f'  $env:PKSL_AES_KEY="{k}"')

            elif choice == "2":
                cn = prompt("PKSL-CA", "CA Common Name")
                years = int(prompt("5", "CA validity (years)"))
                create_ca(common_name=cn, years_valid=years)

            elif choice == "3":
                agent_id = prompt("agent-01", "Agent ID (also cert CN)")
                days = int(prompt("365", "Cert validity (days)"))
                issue_agent_cert(agent_id, days_valid=days)

            elif choice == "4":
                agent_id = prompt("agent-01", "Agent ID (cert file pki/issued/<id>_cert.pem)")
                cert_path = ISSUED_DIR / f"{agent_id}_cert.pem"
                if not cert_path.exists():
                    print(f"[err] Not found: {cert_path}")
                else:
                    show_cert_serial(cert_path)

            elif choice == "5":
                agent_id = prompt("agent-01", "Agent ID to revoke (cert file pki/issued/<id>_cert.pem)")
                cert_path = ISSUED_DIR / f"{agent_id}_cert.pem"
                if not cert_path.exists():
                    print(f"[err] Not found: {cert_path}")
                else:
                    revoke_by_cert_file(cert_path)

            elif choice == "6":
                agent_id = prompt("agent-01", "Agent ID (for Ed25519)")
                generate_ed25519_agent_keys(agent_id)

            elif choice == "7":
                agent_id = prompt("agent-01", "Agent ID (for Noise agent key)")
                generate_noise_keys(agent_id)

            elif choice == "8":
                agent_id = prompt("agent-01", "Agent ID")
                print("\n[step] Ed25519 signing keys...")
                generate_ed25519_agent_keys(agent_id)
                print("\n[step] Noise keys (agent + server)...")
                generate_noise_keys(agent_id)
                print("\n[step] Agent certificate (requires CA)...")
                # Ensure CA exists, if not prompt to create
                paths = ca_paths()
                if not paths.ca_key_path.exists() or not paths.ca_cert_path.exists():
                    print("[info] CA not found. Creating CA first.")
                    create_ca(common_name="PKSL-CA", years_valid=5)
                issue_agent_cert(agent_id, days_valid=365)
                print("\n[ok] DONE for agent:", agent_id)
                print(f"  - Agent cert: pki/issued/{agent_id}_cert.pem")
                print(f"  - Set env:    $env:PKSL_AGENT_CERT=\"pki/issued/{agent_id}_cert.pem\"")

            elif choice == "9":
                print("[ok] exiting.")
                return

            else:
                print("[err] invalid choice.")

        except Exception as e:
            print(f"[err] {e}")


if __name__ == "__main__":
    menu()