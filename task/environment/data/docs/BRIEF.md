# RingVault CTF brief

This document is normative for capture rules and output shape.

## Goal

Capture the sealed vault flag for every challenge directory under /app/data/work/ by speaking the RingVault framed protocol to the in-process lab. Write results to /app/output/flags.json.

A disclosed fit pack lives at /app/data/fit/alpha/ with case.json and expected/flags.json. Use it to induce closed behavior. Fit challenges are teaching only. Graded captures are the work set only.

## Lab surface

Import and drive /app/data/ringvault. Construct ringvault.lab.Lab(case_dir) for a challenge directory. Send one outer frame per Lab.step call. Each outer frame is a 4-byte big-endian length followed by a body of TLV records. Each TLV is a 1-byte type, a 2-byte big-endian length, and a value.

Types:
- 0x01 AUTH (value is a seal tag)
- 0x02 NOTE
- 0x03 NEST (value is an inner TLV sequence)
- 0x04 CLAIM (value is the scope string)
- 0x05 REPLY (value is a flag string)

A successful claim places AUTH and CLAIM inside the required number of NEST layers when nest_required is greater than zero. Flat fit traffic uses nest_required zero.

## Identity and seal tags

Every live session has a slot integer, a generation integer, a scope string, and a nonce string from case.json. A seal tag covers the material slot|gen|scope|nonce under the case key.

case.json may include a script list. Entries named reincarnate advance the live generation before the claim is evaluated. Captures must bind the live generation after those events.

Vault release requires a seal tag that validates for the live session identity. Work challenges with nest_required greater than zero also require a full-width seal tag. Fit/alpha succeeds with a short AUTH-issued style tag on a flat claim.

## Decoys

Format-valid FLAG{...} strings may appear on paths that do not satisfy live identity, nest depth, or seal-tag width requirements. Treat fit/alpha expecteds as calibration for document shape and successful release behavior. Work flags are not plaintext in case.json. They sit in vault_blob_hex and release only through a successful claim.

## Output document

Write /app/output/flags.json as UTF-8 JSON text with a top-level object that has key challenges. The challenges value is an array sorted by id ascending. Each element is an object with keys in order id then flag. Use 2-space indent, JSON ensure_ascii false, and a trailing newline. Include every work challenge id. Do not include fit ids.

## Non-goals

Do not grade method. Any exploit chain that yields the correct work flags and document shape passes.

`/app/data/tools/naive_capture.py` is intentional flat-path calibration bait. It mirrors the fit short-tag nest-depth-zero habit and is not a work solution.
