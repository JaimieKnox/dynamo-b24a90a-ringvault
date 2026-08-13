# RingVault CTF brief

This document is normative for capture rules and output shape.

## Goal

Capture the sealed vault flag for every challenge directory under /app/data/work/ by speaking the RingVault framed protocol to the vaultlab binary. Write results to /app/output/flags.json.

Disclosed fit packs live under /app/data/fit/ with case.json. Use them to induce closed behavior by carefully exercising the binary and comparing REPLY values against the case decoy_flag field. A REPLY that matches decoy_flag means the action was rejected (wrong AUTH tag, stale ticket, wrong nest depth, missing continue binding, or missing hold seal). A REPLY that differs from decoy_flag means the claim succeeded. Fit challenges are teaching only. Graded captures are the work set only.

## Binary surface

The challenge engine is a compiled binary at /app/data/bin/vaultlab. No importable Python package or source code is shipped.

Run: /app/data/bin/vaultlab CASE_DIR

The binary reads case.json from CASE_DIR. Each case.json carries an opaque encrypted schedule blob in the sched_hex field. That blob is interpreted only inside the binary. It is not a readable script and does not document opcodes or encryption. The binary loops on stdin/stdout, processing one protocol step per frame pair until the session is exhausted.

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
- 0x07 CONTINUE (value is a 32-byte continue seal tag)
- 0x08 HOLD_SEAL (value is a 32-byte hold seal tag)

Send one frame to the binary stdin per step. Read one reply frame from its stdout per step. The binary has no public fields or inspectable state. All session state is internal to the process.

## Session schedule

The binary follows a session schedule decoded from the case.json sched_hex opaque blob. The schedule controls when identity state advances, when tickets are issued, when tickets are invalidated, and when the vault claim gate opens. Different cases have different schedules with varying structure and length. Graded work schedules are not identical to any disclosed fit pack. Do not treat sched_hex as a human-readable script.

Induce session structure from the disclosed fit packs and this brief. Fit packs teach composition patterns. Work packs retain held schedule residue. Blind exhaustive probing is a poor strategy because failed ticket requests, failed holds, failed continues, and failed claims lock the session.

Observable replies under a correct planned path:

- A reply carrying TICKET plus NOTE indicates a ticket-issuance gate was consumed. The NOTE value on ticket grants is the opaque string "ok" and does not reveal identity state.
- A reply carrying NOTE with value "acked" indicates a continue binding was accepted.
- A reply carrying NOTE with value "held" indicates a hold gate was accepted.
- A REPLY value matching decoy_flag indicates a rejected or misplaced action.
- A REPLY value not matching decoy_flag on a claim action indicates vault release.

The binary may advance identity state (generation, active nonce, ticket validity) between visible gates. These internal transitions are not directly observable but affect ticket issuance and vault release. The active nonce for each identity epoch is derived engine-internally and is not listed in case.json. Model the current identity epoch by tracking how internal schedule events (ticks, reincarnations) modify identity from the starting values in case.json.

Each fit pack teaches a distinct composition pattern. Alpha is a baseline ticket then claim. Beta exercises ticket lifecycle across identity changes. Gamma exercises a post-ticket identity advance before claim.

## Gate tag

Every gate seal (request, continue, hold, claim) requires a gate_tag appended to the material string. The gate_tag is 16 lowercase hexadecimal characters (8 bytes) that bind the seal to a specific schedule position and gate type. The gate_tag is not present in case.json and cannot be obtained by enumerating gate types or restarting the binary.

The gate_tag for a given gate is the first 8 bytes of SHA-256(engine-internal secret bytes || challenge_id || "|" || script_pos || "|" || event_code), rendered as 16 lowercase hex characters. Here script_pos is the zero-based decimal index of the gate in the decoded schedule, and event_code is the decimal numeric code for the gate type at that position. The engine-internal secret is the same binary-only salt that protects ticket issuance and schedule decryption. It is not disclosed in case.json or this brief.

Gate type codes: tick is 1, reincarnate is 2, ticket is 3, claim is 4, hold is 5. The continue phase shares the same script_pos and event_code as its parent ticket gate.

A solver that has recovered the engine secret and decoded the schedule can compute gate_tags for every position. Without the engine secret, gate_tags are unpredictable (2^64 space per gate).

## Ticket request seal

Ticket gates do not accept a bare NOTE. The caller must send AUTH plus NOTE in one frame. The AUTH value is a request seal tag.

The request seal tag is the SHA-256 digest of these bytes in order: the 32 raw key bytes, one ASCII pipe separator, then the ASCII material string. The material string is slot, scope, the literal word request, and the gate_tag joined by ASCII pipe separators. Example shape: key_bytes + "|" + "slot|scope|request|gate_tag" with decimal slot and no extra spaces.

Fit packs with nest_required zero may accept a short request AUTH tag (minimum 4 bytes prefix of the digest). Work challenges with nest_required greater than zero require the full 32-byte request AUTH tag.

## Ticket lifecycle

Tickets are issued at ticket gates after a valid request seal. A ticket may become invalid during a session if the binary rotates identity state. After invalidation the caller must request a new ticket before claiming. Claiming with a stale or missing ticket returns a decoy. Work cases contain at least one identity rotation that invalidates an earlier ticket, requiring the caller to re-ticket before the final claim.

Tickets are opaque binary values issued by the engine. The ticket bytes bind internal engine state (including the binary-only salt, current generation, and active nonce at issuance time). The caller cannot forge or predict ticket bytes without driving the binary.

## Hold gate

Some sessions include hold gates. A hold gate is not present in the disclosed fit packs. When the schedule reaches a hold gate the binary enters a hold phase. The caller must send a frame that contains a HOLD_SEAL TLV (type 0x08) with a 32-byte hold seal tag. The hold seal tag is the SHA-256 digest of these bytes in order: the 32 raw key bytes, one ASCII pipe separator, then the ASCII material string. The hold material string is the literal "hold" followed by a pipe and the lowercase hex encoding of the live ticket bytes (or a literal dash "-" if no ticket is currently live), followed by a pipe and the gate_tag. Example shapes: key_bytes + "|" + "hold|ticket_hex|gate_tag" when a live ticket exists, or key_bytes + "|" + "hold|-|gate_tag" when no live ticket exists. On success the binary replies with NOTE value "held" and then advances the schedule. A missing, wrong-type, or wrong-value hold frame permanently locks the session and returns a decoy. Work sessions may use hold composition that is not present in fit packs. Graded work schedules are not listed here.

## Continue binding

After every successful ticket grant, the binary enters a continue phase. The caller must send a CONTINUE frame (TLV type 0x07) with a 32-byte continue seal tag before the session schedule will advance past the ticket event. The full 32-byte tag is required for all cases, including fit packs.

The continue seal tag is the SHA-256 digest of these bytes in order: the 32 raw key bytes, one ASCII pipe separator, then the ASCII material string. The continue material string is the literal "cont" followed by a pipe, the lowercase hex encoding of the live ticket bytes, another pipe, and the gate_tag. The continue gate_tag uses the same script_pos and event_code as the parent ticket gate. Example shape: key_bytes + "|" + "cont|ticket_hex|gate_tag".

The continue must bind the live ticket from the grant. If the continue seal is incorrect or if the caller sends any frame other than a valid CONTINUE during the continue phase, the session locks permanently and all further responses are decoy flags.

## Fail-closed locking

The session uses fail-closed locking. The first failed ticket request, failed hold, failed CONTINUE, or failed CLAIM attempt locks the session permanently. Once locked, all further responses from the binary are decoy flags regardless of input. The binary does not signal the lock state explicitly. The caller must construct correct seals on the first attempt. Any case directory may be restarted as a fresh vaultlab process after a lock. Fit packs are for learning. Work packs are graded.

## Identity and claim seal tags

The claim seal tag is the SHA-256 digest of these bytes in order: the 32 raw key bytes, one ASCII pipe separator, then the ASCII material string. The material string is slot, scope, ticket_hex, and gate_tag joined by ASCII pipe separators, where ticket_hex is the lowercase hex encoding of the live ticket bytes. Example shape: key_bytes + "|" + "slot|scope|ticket_hex|gate_tag" with decimal slot and no extra spaces.

Vault release requires:
1. A valid live ticket (issued after the most recent identity rotation)
2. A successful continue binding after the ticket grant
3. A claim seal tag that validates for the live ticket
4. AUTH plus CLAIM plus TICKET TLV records placed at exact nest depth (nest_required NEST layers for work challenges, zero for some fit packs)
5. Full-digest-width (32 bytes) AUTH tag for work challenges with nest_required greater than zero
6. Fit packs with nest_required zero may accept short AUTH tags (minimum 4 bytes)

A successful claim returns the vault flag via REPLY. Any path that misses ticket freshness, request seal, continue binding, hold seal, nest depth, or tag width returns a format-valid decoy FLAG string.

## Decoys

Format-valid FLAG{...} strings appear on paths that miss ticket binding, request seal, continue binding, hold seal, live identity, nest depth, or seal-tag width. Claim success frames carry REPLY only. Ticket-grant frames carry TICKET plus an opaque NOTE. Continue success frames carry NOTE only. Hold success frames carry NOTE with value held. Work flags are not plaintext in case.json. They release only through a successful claim interaction with the binary. Vault keystream and tickets bind an engine-internal secret that is not present in case.json. Compare REPLY against the case decoy_flag to distinguish success from failure when probing fit packs.

## Output document

Write /app/output/flags.json as UTF-8 JSON text with a top-level object that has key challenges. The challenges value is an array sorted by id ascending. Each element is an object with keys in order id then flag. Use 2-space indent, JSON ensure_ascii false, and a trailing newline. Include every work challenge id. Do not include fit ids.

## Non-goals

Do not grade method. Any exploit chain that yields the correct work flags and document shape passes.
