import hashlib
import json
import os

from . import protocol, seal


class Lab:
    def __init__(self, case_dir: str):
        with open(os.path.join(case_dir, "case.json"), "r") as f:
            self.case = json.load(f)

        self.slot: int = self.case["slot"]
        self.gen: int = self.case["gen"]
        self.nest_required: int = self.case["nest_required"]
        self.key: bytes = bytes.fromhex(self.case["key_hex"])
        self.scope: str = self.case["scope"]
        self.nonces: list[str] = list(self.case["nonces"])
        self.nonce_idx: int = 0
        self.vault_blob: bytes = bytes.fromhex(self.case["vault_blob_hex"])
        self.decoy_flag: str = self.case["decoy_flag"]
        self.script: list = list(self.case["script"])
        self.script_pos: int = 0
        self.ticket: bytes | None = None
        self.phase: str = "run"

    @property
    def nonce(self) -> str:
        return self.nonces[self.nonce_idx]

    def _advance_to_gate(self) -> None:
        while self.script_pos < len(self.script):
            event = self.script[self.script_pos]
            if event == "tick":
                self.gen += 1
                self.script_pos += 1
                continue
            if event == "reincarnate":
                self.gen += 1
                self.nonce_idx = min(self.nonce_idx + 1, len(self.nonces) - 1)
                self.script_pos += 1
                continue
            if event in ("ticket", "claim"):
                self.phase = event
                return
            self.script_pos += 1
        self.phase = "done"

    def _issue_ticket(self) -> bytes:
        material = (
            self.key
            + b"|ticket|"
            + str(self.slot).encode()
            + b"|"
            + str(self.gen).encode()
            + b"|"
            + self.nonce.encode()
        )
        self.ticket = hashlib.sha256(material).digest()[:16]
        return self.ticket

    def _unwrap_nested(self, body: bytes, depth: int):
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
        if self.ticket is None:
            return self.decoy_flag

        if self.nest_required > 0:
            inner = self._unwrap_nested(body, self.nest_required)
            if inner is None:
                return self.decoy_flag
        else:
            inner = body

        auth_tag = None
        claim_scope = None
        ticket_val = None
        for typ, val in protocol.decode_tlvs(inner):
            if typ == protocol.TYPE_AUTH:
                auth_tag = val
            elif typ == protocol.TYPE_CLAIM:
                claim_scope = val.decode("utf-8", errors="replace")
            elif typ == protocol.TYPE_TICKET:
                ticket_val = val

        if auth_tag is None or claim_scope is None or ticket_val is None:
            return self.decoy_flag
        if claim_scope != self.scope:
            return self.decoy_flag
        if ticket_val != self.ticket:
            return self.decoy_flag

        material = seal.make_material(
            self.slot, self.gen, self.scope, self.nonce, self.ticket
        )
        computed = seal.compute_tag(self.key, material)

        if self.nest_required == 0:
            if len(auth_tag) < 4:
                return self.decoy_flag
            if computed[: len(auth_tag)] != auth_tag:
                return self.decoy_flag
        else:
            if len(auth_tag) != 32:
                return self.decoy_flag
            if computed != auth_tag:
                return self.decoy_flag

        return seal.decrypt_flag(
            self.vault_blob, self.key, self.slot, self.gen, self.scope
        )

    def step(self, raw_frame: bytes) -> bytes:
        self._advance_to_gate()
        body = protocol.decode_frame(raw_frame)

        if self.phase == "ticket":
            notes = [
                val
                for typ, val in protocol.decode_tlvs(body)
                if typ == protocol.TYPE_NOTE
            ]
            if notes:
                ticket = self._issue_ticket()
                self.script_pos += 1
                self.phase = "run"
                reply = protocol.encode_tlv(protocol.TYPE_TICKET, ticket)
                return protocol.encode_frame(reply)
            reply = protocol.encode_tlv(
                protocol.TYPE_REPLY, self.decoy_flag.encode("utf-8")
            )
            return protocol.encode_frame(reply)

        if self.phase == "claim":
            flag_str = self._check_claim(body)
            self.script_pos += 1
            self.phase = "run"
            reply = protocol.encode_tlv(
                protocol.TYPE_REPLY, flag_str.encode("utf-8")
            )
            return protocol.encode_frame(reply)

        reply = protocol.encode_tlv(
            protocol.TYPE_REPLY, self.decoy_flag.encode("utf-8")
        )
        return protocol.encode_frame(reply)
