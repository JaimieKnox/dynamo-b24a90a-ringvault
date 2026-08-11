# RingVault CTF brief

This document is normative for capture rules and output shape.

## Goal

Capture the sealed vault flag for every challenge directory under /app/data/work/ by speaking the RingVault framed protocol to the in-process lab. Write results to /app/output/flags.json.

Disclosed fit packs live under /app/data/fit/ with case.json and expected/flags.json. Use them to induce closed behavior. Fit challenges are teaching only. Graded captures are the work set only.

## Lab surface

Import and drive /app/data/ringvault. Construct ringvault.lab.Lab(case_dir) for a challenge directory. Send one outer frame per Lab.step call. Each outer frame is a 4-byte big-endian length followed by a body of TLV records. Each TLV is a 1-byte type, a 2-byte big-endian length, and a value.

Types:
- 0x01 AUTH (value is a seal tag)
- 0x02 NOTE
- 0x03 NEST (value is an inner TLV sequence)
- 0x04 CLAIM (value is the scope string)
- 0x05 REPLY (value is a flag string)
- 0x06 TICKET (value is a lab-issued session ticket)

The Lab object has no public fields. All session state is internal. Parse replies from Lab.step return bytes only.

## Scripted session timeline

case.json includes a script list. The lab consumes script events across Lab.step calls:
- tick advances the live generation by one
- reincarnate advances the live generation by one, advances the live nonce to the next entry in the case nonces list, and invalidates the current ticket
- ticket is a gate that waits for a NOTE-bearing frame and replies with TICKET for the live identity
- claim is a gate that waits for a vault claim frame

Each Lab.step call consumes one gate event. Ticks and reincarnates advance automatically before the next gate. The agent must call Lab.step once per gate event in the order they appear in the script.

## Ticket invalidation

A reincarnate event always invalidates any previously issued ticket. After a reincarnate the agent must request a new ticket before claiming. Claiming with a stale or missing ticket returns a decoy. Work cases contain at least one reincarnate after an earlier ticket gate, requiring the agent to re-ticket before the final claim.

## Identity and seal tags

Live identity at claim time is slot, generation (after all preceding ticks and reincarnates), scope, and the active nonce. A seal tag covers material slot|gen|scope|nonce|ticket_hex under the case key (HMAC-like SHA-256 prefix construction), where ticket_hex is the lowercase hex of the most recently issued ticket bytes.

Vault release requires:
1. A valid live ticket (issued after the most recent reincarnate)
2. A seal tag that validates for the live identity and that ticket
3. AUTH plus CLAIM plus TICKET TLV records placed at exact nest depth (nest_required NEST layers for work challenges, zero for some fit packs)
4. Full-digest-width (32 bytes) AUTH tag for work challenges with nest_required greater than zero
5. Fit packs with nest_required zero may accept short AUTH tags (minimum 4 bytes)

A successful claim returns the vault flag via REPLY. Any path that misses ticket freshness, identity binding, nest depth, or tag width returns a format-valid decoy FLAG string.

## Decoys

Format-valid FLAG{...} strings appear on paths that miss ticket binding, live identity, nest depth, or seal-tag width. Reply frames carry REPLY only. Work flags are not plaintext in case.json. They release only through a successful claim interaction with the lab.

## Output document

Write /app/output/flags.json as UTF-8 JSON text with a top-level object that has key challenges. The challenges value is an array sorted by id ascending. Each element is an object with keys in order id then flag. Use 2-space indent, JSON ensure_ascii false, and a trailing newline. Include every work challenge id. Do not include fit ids.

## Non-goals

Do not grade method. Any exploit chain that yields the correct work flags and document shape passes.
