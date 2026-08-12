# RingVault CTF brief

This document is normative for capture rules and output shape.

## Goal

Capture the sealed vault flag for every challenge directory under /app/data/work/ by speaking the RingVault framed protocol to the vaultlab binary. Write results to /app/output/flags.json.

Disclosed fit packs live under /app/data/fit/ with case.json. Use them to induce closed behavior by probing the binary and comparing REPLY values against the case decoy_flag field. A REPLY that matches decoy_flag means the claim was rejected (wrong AUTH tag, stale ticket, wrong nest depth, or missing binding). A REPLY that differs from decoy_flag means the claim succeeded. Fit challenges are teaching only. Graded captures are the work set only.

## Binary surface

The challenge engine is a compiled binary at /app/data/bin/vaultlab. No importable Python package or source code is shipped.

Run: /app/data/bin/vaultlab CASE_DIR

The binary reads case.json and an opaque session schedule from CASE_DIR. It then loops on stdin/stdout, processing one protocol step per frame pair until the session is exhausted.

## Frame protocol

Each message (both directions) is a length-prefixed binary frame: a 4-byte big-endian unsigned integer giving the body length, followed by that many body bytes. The body is a concatenation of TLV records.

Each TLV record: 1-byte type, 2-byte big-endian value length, then value bytes.

Types:
- 0x01 AUTH (value is a seal tag)
- 0x02 NOTE (value is arbitrary session data)
- 0x03 NEST (value is an inner TLV sequence)
- 0x04 CLAIM (value is the scope string)
- 0x05 REPLY (value is a flag string)
- 0x06 TICKET (value is a binary session ticket)

Send one frame to the binary stdin per step. Read one reply frame from its stdout per step. The binary has no public fields or inspectable state. All session state is internal to the process.

## Session schedule

The binary follows an internal session schedule that is opaque to the caller. The schedule controls when identity state advances, when tickets are issued, when tickets are invalidated, and when the vault claim gate opens. Different cases have different schedules with varying structure and length.

The caller must discover the session structure by probing the binary and observing reply types:

- A reply carrying TICKET plus NOTE indicates a ticket-issuance gate was consumed. The NOTE value is session data from the binary at that point.
- A REPLY value matching decoy_flag indicates a rejected or misplaced action.
- A REPLY value not matching decoy_flag on a claim action indicates vault release.

The binary may advance identity state (generation, active nonce, ticket validity) between visible gates. These internal transitions are not directly observable but affect the claim-time identity that the seal must bind.

Use disclosed fit packs to learn the binary interaction model before attacking work cases. Each fit pack teaches a distinct composition pattern. Alpha is a baseline. Beta exercises ticket lifecycle across identity changes. Gamma exercises a distinct identity binding pattern that differs from the simpler cases.

## Ticket lifecycle

Tickets are issued at ticket gates. A ticket may become invalid during a session if the binary rotates identity state. After invalidation the caller must request a new ticket before claiming. Claiming with a stale or missing ticket returns a decoy. Work cases contain at least one identity rotation that invalidates an earlier ticket, requiring the caller to re-ticket before the final claim.

## Identity and seal tags

The seal tag is the SHA-256 digest of these bytes in order: the 32 raw key bytes, one ASCII pipe separator, then the ASCII material string. The material string is slot, gen, scope, nonce, and ticket_hex joined by ASCII pipe separators, where ticket_hex is the lowercase hex encoding of the live ticket bytes. Example shape: key_bytes + "|" + "slot|gen|scope|nonce|ticket_hex" with decimal slot and gen and no extra spaces.

The seal must bind the live identity at claim time. The identity state at claim may differ from the state observed at ticket issuance if internal session events intervene.

Vault release requires:
1. A valid live ticket (issued after the most recent identity rotation)
2. A seal tag that validates for the live claim-time identity and that ticket
3. AUTH plus CLAIM plus TICKET TLV records placed at exact nest depth (nest_required NEST layers for work challenges, zero for some fit packs)
4. Full-digest-width (32 bytes) AUTH tag for work challenges with nest_required greater than zero
5. Fit packs with nest_required zero may accept short AUTH tags (minimum 4 bytes)

A successful claim returns the vault flag via REPLY. Any path that misses ticket freshness, identity binding, nest depth, or tag width returns a format-valid decoy FLAG string.

## Decoys

Format-valid FLAG{...} strings appear on paths that miss ticket binding, live identity, nest depth, or seal-tag width. Claim success frames carry REPLY only. Ticket-grant frames carry TICKET plus a generation NOTE. Work flags are not plaintext in case.json. They release only through a successful claim interaction with the binary. Compare REPLY against the case decoy_flag to distinguish success from failure when probing fit packs.

## Output document

Write /app/output/flags.json as UTF-8 JSON text with a top-level object that has key challenges. The challenges value is an array sorted by id ascending. Each element is an object with keys in order id then flag. Use 2-space indent, JSON ensure_ascii false, and a trailing newline. Include every work challenge id. Do not include fit ids.

## Non-goals

Do not grade method. Any exploit chain that yields the correct work flags and document shape passes.
