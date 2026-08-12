Capture sealed RingVault flags for every challenge directory under /app/data/work/. The normative contract is /app/data/docs/BRIEF.md.

Drive the challenge binary at /app/data/bin/vaultlab for each work case. The binary speaks a length-prefixed frame protocol on stdin/stdout and has no inspectable internal state. Each case follows an internal session schedule embedded in the binary. Schedules are not present as files in case directories. Ticket gates require a request seal AUTH plus NOTE. After each ticket grant the session demands a CONTINUE seal before advancing. Failed ticket requests, continues, or claims lock the process. Parse session outcomes from reply frames. Induce framing, ticket lifecycle, request and continue seals, claim seals, nesting, and identity binding from the brief and fit-pack practice. Compare REPLY values against each case decoy_flag to distinguish success from failure when practicing on fit packs. Write /app/output/flags.json for the work set only.

Success criteria:
1. /app/output/flags.json exists as an ordinary file (not a symlink).
2. Top-level object has challenges array. Each element uses keys in order id then flag.
3. Challenge ids are sorted ascending and include every work directory name under /app/data/work/.
4. Serialized bytes match BRIEF formatting (2-space indent, ensure_ascii false, trailing newline).
5. Each work flag matches the vault release obtained under BRIEF rules for that case.
