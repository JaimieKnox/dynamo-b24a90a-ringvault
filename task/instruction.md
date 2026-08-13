Capture sealed RingVault flags for every challenge directory under /app/data/work/. The normative contract is /app/data/docs/BRIEF.md.

Drive the challenge binary at /app/data/bin/vaultlab for each work case. The binary is statically linked and speaks a length-prefixed frame protocol on stdin/stdout with no inspectable internal state. Each case.json includes an opaque encrypted schedule blob (sched_hex) interpreted only inside the binary. It is not a readable script. Ticket gates require a request seal AUTH plus NOTE. After each ticket grant the session demands a CONTINUE seal before advancing. Hold gates require a HOLD_SEAL TLV (type 0x08) with a 32-byte hold seal tag binding key, hold literal, and live ticket hex or dash. All seal materials end with a pipe followed by 8 raw binary gate_tag bytes (not hex-encoded). Failed ticket requests, continues, holds, or claims lock the process. Parse session outcomes from reply frames. Induce framing, ticket lifecycle, request and continue seals, claim seals, hold seals, nesting, and ticket binding from the brief and fit-pack practice. Compare REPLY values against each case decoy_flag to distinguish success from failure when practicing on fit packs. Write /app/output/flags.json for the work set only.

Success criteria:
1. /app/output/flags.json exists as an ordinary file (not a symlink).
2. Top-level object has challenges array. Each element uses keys in order id then flag.
3. Challenge ids are sorted ascending and include every work directory name under /app/data/work/.
4. Serialized bytes match BRIEF formatting (2-space indent, ensure_ascii false, trailing newline).
5. Each work flag matches the vault release obtained under BRIEF rules for that case.
