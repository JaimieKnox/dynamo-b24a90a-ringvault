import hashlib
import json
import os
import weakref

from . import protocol, seal

# Instance session state is not stored as readable Lab attributes.
_SESS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


class Lab:
    def __init__(self, case_dir: str):
        with open(os.path.join(case_dir, 'case.json'), 'r') as f:
            case = json.load(f)

        _SESS[self] = {
            'slot': case['slot'],
            'gen': case['gen'],
            'nest_required': case['nest_required'],
            'key': bytes.fromhex(case['key_hex']),
            'scope': case['scope'],
            'nonces': list(case['nonces']),
            'nonce_idx': 0,
            'vault_blob': bytes.fromhex(case['vault_blob_hex']),
            'decoy_flag': case['decoy_flag'],
            'script': list(case['script']),
            'script_pos': 0,
            'ticket': None,
            'phase': 'run',
        }

    def __getattribute__(self, name: str):
        if name.startswith('_Lab__') or name in {'_sess', '__dict__'}:
            raise AttributeError(name)
        return object.__getattribute__(self, name)

    def _advance_to_gate(self) -> None:
        s = _SESS[self]
        while s['script_pos'] < len(s['script']):
            event = s['script'][s['script_pos']]
            if event == 'tick':
                s['gen'] += 1
                s['script_pos'] += 1
                continue
            if event == 'reincarnate':
                s['gen'] += 1
                s['nonce_idx'] = min(s['nonce_idx'] + 1, len(s['nonces']) - 1)
                s['ticket'] = None
                s['script_pos'] += 1
                continue
            if event in ('ticket', 'claim'):
                s['phase'] = event
                return
            s['script_pos'] += 1
        s['phase'] = 'done'

    def _issue_ticket(self) -> bytes:
        s = _SESS[self]
        material = (
            s['key']
            + b'|ticket|'
            + str(s['slot']).encode()
            + b'|'
            + str(s['gen']).encode()
            + b'|'
            + s['nonces'][s['nonce_idx']].encode()
        )
        s['ticket'] = hashlib.sha256(material).digest()[:16]
        return s['ticket']

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
        s = _SESS[self]
        if s['ticket'] is None:
            return s['decoy_flag']

        if s['nest_required'] > 0:
            inner = self._unwrap_nested(body, s['nest_required'])
            if inner is None:
                return s['decoy_flag']
            for typ, _ in protocol.decode_tlvs(body):
                if typ != protocol.TYPE_NEST:
                    return s['decoy_flag']
                break
        else:
            inner = body

        auth_tag = None
        claim_scope = None
        ticket_val = None
        for typ, val in protocol.decode_tlvs(inner):
            if typ == protocol.TYPE_AUTH:
                auth_tag = val
            elif typ == protocol.TYPE_CLAIM:
                claim_scope = val.decode('utf-8', errors='replace')
            elif typ == protocol.TYPE_TICKET:
                ticket_val = val

        if auth_tag is None or claim_scope is None or ticket_val is None:
            return s['decoy_flag']
        if claim_scope != s['scope']:
            return s['decoy_flag']
        if ticket_val != s['ticket']:
            return s['decoy_flag']

        material = seal.make_material(
            s['slot'], s['gen'], s['scope'],
            s['nonces'][s['nonce_idx']], s['ticket']
        )
        computed = seal.compute_tag(s['key'], material)

        if s['nest_required'] == 0:
            if len(auth_tag) < 4:
                return s['decoy_flag']
            if computed[: len(auth_tag)] != auth_tag:
                return s['decoy_flag']
        else:
            if len(auth_tag) != 32:
                return s['decoy_flag']
            if computed != auth_tag:
                return s['decoy_flag']

        return seal._decrypt_flag(
            s['vault_blob'], s['key'], s['slot'], s['gen'],
            s['scope'], s['ticket']
        )

    def step(self, raw_frame: bytes) -> bytes:
        s = _SESS[self]
        self._advance_to_gate()
        body = protocol.decode_frame(raw_frame)

        if s['phase'] == 'ticket':
            notes = [
                val
                for typ, val in protocol.decode_tlvs(body)
                if typ == protocol.TYPE_NOTE
            ]
            if notes:
                ticket = self._issue_ticket()
                s['script_pos'] += 1
                s['phase'] = 'run'
                reply = protocol.encode_tlv(protocol.TYPE_TICKET, ticket)
                return protocol.encode_frame(reply)
            reply = protocol.encode_tlv(
                protocol.TYPE_REPLY, s['decoy_flag'].encode('utf-8')
            )
            return protocol.encode_frame(reply)

        if s['phase'] == 'claim':
            flag_str = self._check_claim(body)
            s['script_pos'] += 1
            s['phase'] = 'run'
            reply = protocol.encode_tlv(
                protocol.TYPE_REPLY, flag_str.encode('utf-8')
            )
            return protocol.encode_frame(reply)

        reply = protocol.encode_tlv(
            protocol.TYPE_REPLY, s['decoy_flag'].encode('utf-8')
        )
        return protocol.encode_frame(reply)
