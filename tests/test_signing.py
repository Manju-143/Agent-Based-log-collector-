from pksl.crypto.signing import generate_ed25519_keypair, sign_bytes, verify_bytes


def test_signature_verify_ok():
    kp = generate_ed25519_keypair()
    msg = b'{"v":1,"agent_id":"agent-01","seq":1,"record":{"msg":"hi"}}'

    sig_b64 = sign_bytes(kp.private, msg)
    assert verify_bytes(kp.public, msg, sig_b64) is True


def test_signature_verify_fails_if_message_changes():
    kp = generate_ed25519_keypair()
    msg = b"hello"
    sig_b64 = sign_bytes(kp.private, msg)

    tampered = b"hello!"
    assert verify_bytes(kp.public, tampered, sig_b64) is False