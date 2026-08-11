"""
RingVault lab server -- deterministic step-based CTF challenge engine.

Lab(case_dir) loads a case.json and processes raw framed messages.
step(raw_frame_bytes) -> reply_frame_bytes

The lab manages session identity (slot, gen), processes reincarnation
events from the case script, and gates vault release on correct
full-width generation-bound capability proof.
"""

import json
import os

from . import protocol, seal


class Lab:
    """Deterministic step-based RingVault challenge server."""

    def __init__(self, case_dir: str):
        with open(os.path.join(case_dir, "case.json"), "r") as f:
            self.case = json.load(f)

        self.slot: int = self.case["slot"]
        self.gen: int = self.case["gen"]
        self.nest_required: int = self.case["nest_required"]
        self.key: bytes = bytes.fromhex(self.case["key_hex"])
        self.scope: str = self.case["scope"]
        self.nonce: str = self.case["nonce"]
        self.vault_blob: bytes = bytes.fromhex(self.case["vault_blob_hex"])
        self.decoy_flag: str = self.case["decoy_flag"]
        self.script: list = list(self.case["script"])
        self.script_pos: int = 0

    def _current_material(self) -> bytes:
        """Material string that must be signed for vault access."""
        return seal.make_material(self.slot, self.gen, self.scope, self.nonce)

    def _unwrap_nested(self, body: bytes, depth: int):
        """
        Unwrap exactly *depth* NEST layers and return the inner TLV sequence.
        Returns None if nesting is insufficient.
        """
        current = body
        for _ in range(depth):
            found_nest = False
            for typ, val in protocol.decode_tlvs(current):
                if typ == protocol.TYPE_NEST:
                    current = val
                    found_nest = True
                    break
            if not found_nest:
                return None
        return current

    def _check_claim(self, body: bytes):
        """
        Validate a CLAIM frame and return (flag_string, is_real).

        For flat cases (nest_required=0): short tags (>= 4 bytes) are
        sufficient for real vault release.

        For nested cases (nest_required >= 1): full-width tags (>= 16 bytes)
        bound to the current generation are required for real release.
        """
        if self.nest_required > 0:
            inner = self._unwrap_nested(body, self.nest_required)
            if inner is None:
                return self.decoy_flag, False
        else:
            inner = body

        auth_tag = None
        claim_scope = None
        for typ, val in protocol.decode_tlvs(inner):
            if typ == protocol.TYPE_AUTH:
                auth_tag = val
            elif typ == protocol.TYPE_CLAIM:
                claim_scope = val.decode("utf-8", errors="replace")

        if auth_tag is None or claim_scope is None:
            return self.decoy_flag, False

        if claim_scope != self.scope:
            return self.decoy_flag, False

        material = self._current_material()
        computed = seal.compute_tag(self.key, material)

        if len(auth_tag) < 4:
            return self.decoy_flag, False

        if computed[: len(auth_tag)] != auth_tag:
            return self.decoy_flag, False

        if self.nest_required == 0:
            real_flag = seal.decrypt_flag(
                self.vault_blob, self.key, self.slot, self.gen, self.scope
            )
            return real_flag, True
        else:
            if len(auth_tag) >= 16:
                real_flag = seal.decrypt_flag(
                    self.vault_blob, self.key, self.slot, self.gen, self.scope
                )
                return real_flag, True
            else:
                return self.decoy_flag, False

    def step(self, raw_frame: bytes) -> bytes:
        """
        Process one framed message and return a framed reply.

        Before processing the claim, the lab runs pending script events
        (reincarnation, etc.).
        """
        while self.script_pos < len(self.script):
            event = self.script[self.script_pos]
            if event == "reincarnate":
                self.gen += 1
                self.script_pos += 1
            else:
                self.script_pos += 1
                break

        body = protocol.decode_frame(raw_frame)
        flag_str, is_real = self._check_claim(body)

        tag = b"real" if is_real else b"decoy"
        reply_body = (
            protocol.encode_tlv(protocol.TYPE_NOTE, tag)
            + protocol.encode_tlv(protocol.TYPE_REPLY, flag_str.encode("utf-8"))
        )
        return protocol.encode_frame(reply_body)
