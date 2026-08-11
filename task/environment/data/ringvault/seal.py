"""
Seal-tag computation and vault blob encryption for RingVault.

Seal tag = sha256(key + b"|" + material).digest()

Vault blob = XOR of real_flag bytes with a keystream derived from
  sha256(key + b"|" + str(slot) + b"|" + str(gen) + b"|" + scope + b"|open").digest()
repeated as needed.
"""

import hashlib


def compute_tag(key: bytes, material: bytes) -> bytes:
    """Full 32-byte seal tag."""
    return hashlib.sha256(key + b"|" + material).digest()


def compute_tag_truncated(key: bytes, material: bytes, length: int = 4) -> bytes:
    """Truncated seal tag (for fit-issued short tags)."""
    return compute_tag(key, material)[:length]


def make_material(slot: int, gen: int, scope: str, nonce: str) -> bytes:
    """Build the material string for seal tag computation."""
    return f"{slot}|{gen}|{scope}|{nonce}".encode()


def vault_keystream(key: bytes, slot: int, gen: int, scope: str) -> bytes:
    """Derive the keystream used to encrypt/decrypt the vault blob."""
    material = (
        str(slot).encode()
        + b"|"
        + str(gen).encode()
        + b"|"
        + scope.encode()
        + b"|open"
    )
    return hashlib.sha256(key + b"|" + material).digest()


def encrypt_flag(flag: str, key: bytes, slot: int, gen: int, scope: str) -> bytes:
    """XOR-encrypt a flag string under the vault keystream."""
    ks = vault_keystream(key, slot, gen, scope)
    flag_bytes = flag.encode("utf-8")
    out = bytearray(len(flag_bytes))
    for i, b in enumerate(flag_bytes):
        out[i] = b ^ ks[i % len(ks)]
    return bytes(out)


def decrypt_flag(blob: bytes, key: bytes, slot: int, gen: int, scope: str) -> str:
    """XOR-decrypt a vault blob back to a flag string."""
    ks = vault_keystream(key, slot, gen, scope)
    out = bytearray(len(blob))
    for i, b in enumerate(blob):
        out[i] = b ^ ks[i % len(ks)]
    return out.decode("utf-8")
