# RingVault CTF brief

This document is normative for capture rules and output shape.

## Goal

Capture the sealed vault flag for every challenge directory under /app/data/work/ by speaking the RingVault framed protocol to the vaultlab binary. Write results to /app/output/flags.json.

Disclosed fit packs live under /app/data/fit/ with case.json. Use them to induce closed behavior by probing the binary and comparing REPLY values against the case decoy_flag field. A REPLY that matches decoy_flag means the claim was rejected (wrong AUTH tag, stale ticket, wrong nest depth, or missing binding). A REPLY that differs from decoy_flag means the claim succeeded. Fit challenges are teaching only. Graded captures are the work set only.

## Binary surface

The challenge engine is a compiled binary at /app/data/bin/vaultlab. No importable Python package or source code is shipped.

Run: /app/data/bin/vaultlab CASE_DIR

The binary reads case.json from CASE_DIR. It then loops on stdin/stdout, processing one protocol step per frame pair until the session script is exhausted.

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

## Scripted session timeline

case.json includes a script list. The binary consumes script events across frame exchanges:
- tick advances the live generation by one
- reincarnate advances the live generation by one, advances the live nonce to the next entry in the case nonces list, and invalidates the current ticket
- ticket is a gate that waits for a NOTE-bearing frame and replies with TICKET for the live identity plus a NOTE whose value is the live generation as decimal ASCII
- claim is a gate that waits for a vault claim frame

Each frame exchange consumes one gate event. Ticks and reincarnates advance automatically before the next gate. The caller must send one frame per gate event in the order they appear in the script.

Ticks may occur between a ticket issuance and a claim. The live generation at claim time includes all preceding ticks and reincarnates since the script began. A ticket remains valid across ticks but is invalidated by reincarnate. The seal tag must bind the generation that is live at claim, which may differ from the generation reported in the most recent ticket-grant NOTE if any ticks intervened. Fit pack gamma demonstrates this pattern.

## Ticket invalidation

A reincarnate event always invalidates any previously issued ticket. After a reincarnate the caller must request a new ticket before claiming. Claiming with a stale or missing ticket returns a decoy. Work cases contain at least one reincarnate after an earlier ticket gate, requiring the caller to re-ticket before the final claim.

## Identity and seal tags

Live identity at claim time is slot, generation (after all preceding ticks and reincarnates), scope, and the active nonce. The seal tag is the SHA-256 digest of these bytes in order: the 32 raw key bytes, one ASCII pipe separator, then the ASCII material string. The material string is slot, gen, scope, nonce, and ticket_hex joined by ASCII pipe separators, where ticket_hex is the lowercase hex encoding of the live ticket bytes. Example shape: key_bytes + "|" + "slot|gen|scope|nonce|ticket_hex" with decimal slot and gen and no extra spaces.

Vault release requires:
1. A valid live ticket (issued after the most recent reincarnate)
2. A seal tag that validates for the live claim-time identity and that ticket
3. AUTH plus CLAIM plus TICKET TLV records placed at exact nest depth (nest_required NEST layers for work challenges, zero for some fit packs)
4. Full-digest-width (32 bytes) AUTH tag for work challenges with nest_required greater than zero
5. Fit packs with nest_required zero may accept short AUTH tags (minimum 4 bytes)

Important: the generation bound in the seal tag is the live generation at claim time. Ticket-grant replies include a NOTE with the generation at ticket issue. If any tick events run after that ticket grant, claim-time generation is higher than the ticket-grant NOTE. Fit pack gamma demonstrates ticket then tick then claim. Reusing the ticket-grant generation after a later tick returns a decoy.

A successful claim returns the vault flag via REPLY. Any path that misses ticket freshness, identity binding, nest depth, or tag width returns a format-valid decoy FLAG string.

## Decoys

Format-valid FLAG{...} strings appear on paths that miss ticket binding, live identity, nest depth, or seal-tag width. Claim success frames carry REPLY only. Ticket-grant frames carry TICKET plus a generation NOTE. Work flags are not plaintext in case.json. They release only through a successful claim interaction with the binary. Compare REPLY against the case decoy_flag to distinguish success from failure when probing fit packs.

## Output document

Write /app/output/flags.json as UTF-8 JSON text with a top-level object that has key challenges. The challenges value is an array sorted by id ascending. Each element is an object with keys in order id then flag. Use 2-space indent, JSON ensure_ascii false, and a trailing newline. Include every work challenge id. Do not include fit ids.

## Non-goals

Do not grade method. Any exploit chain that yields the correct work flags and document shape passes.
