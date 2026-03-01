import pytest
from pksl.crypto.aead import generate_key_256, encrypt_aesgcm, decrypt_aesgcm
def test_aesgcm_roundtrip_ok():
    key = generate_key_256()
    plaintext = b'{"event":"login","user":"alice"}'
    aad = b"agent-01|1|prevhash|hash|v1"
    enc = encrypt_aesgcm(key, plaintext, aad)
    out = decrypt_aesgcm(key, enc.nonce_b64, enc.ciphertext_b64, aad)
    assert out == plaintext
def test_aesgcm_tamper_ciphertext_fails():
    key = generate_key_256()
    plaintext = b"hello"
    aad = b"aad"
    enc = encrypt_aesgcm(key, plaintext, aad)
    import base64
    ct = bytearray(base64.b64decode(enc.ciphertext_b64.encode("ascii")))
    ct[0] ^= 0x01
    tampered_ct_b64 = base64.b64encode(bytes(ct)).decode("ascii")

    with pytest.raises(Exception):
        decrypt_aesgcm(key, enc.nonce_b64, tampered_ct_b64, aad)
def test_aesgcm_tamper_aad_fails():
    key = generate_key_256()
    plaintext = b"hello"
    aad = b"aad"
    wrong_aad = b"aad_modified"
    enc = encrypt_aesgcm(key, plaintext, aad)
    with pytest.raises(Exception):
        decrypt_aesgcm(key, enc.nonce_b64, enc.ciphertext_b64, wrong_aad)