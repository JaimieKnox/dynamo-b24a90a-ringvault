import hashlib


def compute_tag(key: bytes, material: bytes) -> bytes:
    return hashlib.sha256(key + b"|" + material).digest()


def make_material(slot: int, gen: int, scope: str, nonce: str, ticket: bytes) -> bytes:
    return f"{slot}|{gen}|{scope}|{nonce}|{ticket.hex()}".encode()


def vault_keystream(key: bytes, slot: int, gen: int, scope: str) -> bytes:
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
    ks = vault_keystream(key, slot, gen, scope)
    flag_bytes = flag.encode("utf-8")
    out = bytearray(len(flag_bytes))
    for i, b in enumerate(flag_bytes):
        out[i] = b ^ ks[i % len(ks)]
    return bytes(out)


def decrypt_flag(blob: bytes, key: bytes, slot: int, gen: int, scope: str) -> str:
    ks = vault_keystream(key, slot, gen, scope)
    out = bytearray(len(blob))
    for i, b in enumerate(blob):
        out[i] = b ^ ks[i % len(ks)]
    return out.decode("utf-8")
