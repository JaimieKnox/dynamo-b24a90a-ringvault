# RingVault CTF brief

This document is normative for capture rules and output shape.

## Goal

Capture the sealed vault flag for every challenge directory under /app/data/work/ by speaking the RingVault framed protocol to the vaultlab binary. Write results to /app/output/flags.json.

Disclosed fit packs live under /app/data/fit/ with case.json. Use them to induce closed behavior by carefully exercising the binary and comparing REPLY values against the case decoy_flag field. A REPLY that matches decoy_flag means the action was rejected (wrong AUTH tag, stale ticket, wrong nest depth, missing continue binding, or missing request seal). A REPLY that differs from decoy_flag means the claim succeeded. Fit challenges are teaching only. Graded captures are the work set only.

## Binary surface

The challenge engine is a compiled binary at /app/data/bin/vaultlab. No importable Python package or source code is shipped.

Run: /app/data/bin/vaultlab CASE_DIR

The binary reads case.json from CASE_DIR and follows an internal session schedule embedded in the binary itself. Session schedules are not stored in case directories and are not accessible to the caller. The binary loops on stdin/stdout, processing one protocol step per frame pair until the session is exhausted.

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

Send one frame to the binary stdin per step. Read one reply frame from its stdout per step. The binary has no public fields or inspectable state. All session state is internal to the process.

## Session schedule

The binary follows an internal session schedule embedded in the compiled binary, keyed by the challenge_id from case.json. Session schedules are not stored as files in case directories and cannot be extracted from case data. The schedule controls when identity state advances, when tickets are issued, when tickets are invalidated, and when the vault claim gate opens. Different cases have different schedules with varying structure and length. Graded work schedules are not identical to any disclosed fit pack.

Induce session structure from the disclosed fit packs and this brief. Fit packs teach composition patterns. Work packs retain held schedule residue. Blind exhaustive probing is a poor strategy because failed ticket requests, failed continues, and failed claims lock the session.

Observable replies under a correct planned path:

- A reply carrying TICKET plus NOTE indicates a ticket-issuance gate was consumed. The NOTE value on ticket grants is the opaque string "ok" and does not reveal identity state.
- A reply carrying NOTE with value "acked" indicates a continue binding was accepted.
- A REPLY value matching decoy_flag indicates a rejected or misplaced action.
- A REPLY value not matching decoy_flag on a claim action indicates vault release.

The binary may advance identity state (generation, active nonce, ticket validity) between visible gates. These internal transitions are not directly observable but affect the claim-time identity that the seal must bind. Model the current generation and nonce index by tracking how internal schedule events (ticks, reincarnations) modify identity from the starting values in case.json.

Each fit pack teaches a distinct composition pattern. Alpha is a baseline ticket then claim. Beta exercises ticket lifecycle across identity changes. Gamma exercises a post-ticket identity advance before claim.

## Ticket request seal

Ticket gates do not accept a bare NOTE. The caller must send AUTH plus NOTE in one frame. The AUTH value is a request seal tag.

The request seal tag is the SHA-256 digest of these bytes in order: the 32 raw key bytes, one ASCII pipe separator, then the ASCII material string. The material string is slot, gen, scope, nonce, and the literal word request joined by ASCII pipe separators. Example shape: key_bytes + "|" + "slot|gen|scope|nonce|request" with decimal slot and gen and no extra spaces.

Fit packs with nest_required zero may accept a short request AUTH tag (minimum 4 bytes prefix of the digest). Work challenges with nest_required greater than zero require the full 32-byte request AUTH tag.

## Ticket lifecycle

Tickets are issued at ticket gates after a valid request seal. A ticket may become invalid during a session if the binary rotates identity state. After invalidation the caller must request a new ticket before claiming. Claiming with a stale or missing ticket returns a decoy. Work cases contain at least one identity rotation that invalidates an earlier ticket, requiring the caller to re-ticket before the final claim.

## Continue binding

After every successful ticket grant, the binary enters a continue phase. The caller must send a CONTINUE frame (TLV type 0x07) with a 32-byte continue seal tag before the session schedule will advance past the ticket event. The full 32-byte tag is required for all cases, including fit packs.

The continue seal tag is the SHA-256 digest of these bytes in order: the 32 raw key bytes, one ASCII pipe separator, then the ASCII material string. The continue material string is the literal "cont" followed by slot, gen, nonce, and ticket_hex all joined by ASCII pipe separators. Example shape: key_bytes + "|" + "cont|slot|gen|nonce|ticket_hex" with decimal slot and gen.

The continue must bind the live identity at the point of the ticket grant. If the continue seal is incorrect or if the caller sends any frame other than a valid CONTINUE during the continue phase, the session locks permanently and all further responses are decoy flags.

## Fail-closed locking

The session uses fail-closed locking. The first failed ticket request, failed CONTINUE, or failed CLAIM attempt locks the session permanently. Once locked, all further responses from the binary are decoy flags regardless of input. The binary does not signal the lock state explicitly. The caller must construct correct seals on the first attempt. Fit packs may be restarted as new processes while learning.

## Identity and claim seal tags

The claim seal tag is the SHA-256 digest of these bytes in order: the 32 raw key bytes, one ASCII pipe separator, then the ASCII material string. The material string is slot, gen, scope, nonce, and ticket_hex joined by ASCII pipe separators, where ticket_hex is the lowercase hex encoding of the live ticket bytes. Example shape: key_bytes + "|" + "slot|gen|scope|nonce|ticket_hex" with decimal slot and gen and no extra spaces.

The request and continue seals use the same digest construction with their own material strings as defined above.

The claim seal must bind the live identity at claim time. The identity state at claim may differ from the state at ticket issuance if internal session events intervene. Model identity changes (generation increments from ticks, generation and nonce rotation from reincarnations) to compute the correct claim-time seal. The ticket NOTE does not reveal the current generation.

Vault release requires:
1. A valid live ticket (issued after the most recent identity rotation)
2. A successful continue binding after the ticket grant
3. A claim seal tag that validates for the live claim-time identity and that ticket
4. AUTH plus CLAIM plus TICKET TLV records placed at exact nest depth (nest_required NEST layers for work challenges, zero for some fit packs)
5. Full-digest-width (32 bytes) AUTH tag for work challenges with nest_required greater than zero
6. Fit packs with nest_required zero may accept short AUTH tags (minimum 4 bytes)

A successful claim returns the vault flag via REPLY. Any path that misses ticket freshness, request seal, continue binding, identity binding, nest depth, or tag width returns a format-valid decoy FLAG string.

## Decoys

Format-valid FLAG{...} strings appear on paths that miss ticket binding, request seal, continue binding, live identity, nest depth, or seal-tag width. Claim success frames carry REPLY only. Ticket-grant frames carry TICKET plus an opaque NOTE. Continue success frames carry NOTE only. Work flags are not plaintext in case.json. They release only through a successful claim interaction with the binary. Compare REPLY against the case decoy_flag to distinguish success from failure when probing fit packs.

## Output document

Write /app/output/flags.json as UTF-8 JSON text with a top-level object that has key challenges. The challenges value is an array sorted by id ascending. Each element is an object with keys in order id then flag. Use 2-space indent, JSON ensure_ascii false, and a trailing newline. Include every work challenge id. Do not include fit ids.

## Non-goals

Do not grade method. Any exploit chain that yields the correct work flags and document shape passes.
