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

## Scripted session timeline

case.json includes a script list. The lab consumes script events across Lab.step calls:
- tick advances the live generation by one
- reincarnate advances the live generation by one and advances the live nonce to the next entry in the case nonces list
- ticket is a gate that waits for a NOTE-bearing frame and replies with TICKET for the live identity
- claim is a gate that waits for a vault claim frame

Captures must obtain a ticket after timeline events that precede the ticket gate, then claim under the live identity that exists at that moment.

## Identity and seal tags

Live identity is slot, generation, scope, and the active nonce from nonces. A seal tag covers material slot|gen|scope|nonce|ticket_hex under the case key, where ticket_hex is the lowercase hex of the issued ticket bytes.

Vault release requires a seal tag that validates for that live identity and the issued ticket. Work challenges with nest_required greater than zero require an exact full-digest-width AUTH tag and AUTH plus CLAIM plus TICKET placed under nest_required NEST layers. Fit packs may accept short AUTH tags on flat claims once a ticket is held.

## Decoys

Format-valid FLAG{...} strings may appear on paths that miss ticket binding, live identity, nest depth, or seal-tag width. Reply frames carry REPLY only. Work flags are not plaintext in case.json. They sit in vault_blob_hex and release only through a successful claim.

## Output document

Write /app/output/flags.json as UTF-8 JSON text with a top-level object that has key challenges. The challenges value is an array sorted by id ascending. Each element is an object with keys in order id then flag. Use 2-space indent, JSON ensure_ascii false, and a trailing newline. Include every work challenge id. Do not include fit ids.

## Non-goals

Do not grade method. Any exploit chain that yields the correct work flags and document shape passes.
