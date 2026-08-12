Capture sealed RingVault flags for every challenge directory under /app/data/work/. The normative contract is /app/data/docs/BRIEF.md.

Drive the challenge binary at /app/data/bin/vaultlab for each work case. The binary speaks a length-prefixed frame protocol on stdin/stdout and has no inspectable internal state. Each case follows an opaque internal session schedule that the caller must induce by probing. Parse all session state from reply frames. Disclosed fit packs are under /app/data/fit/. Induce framing, ticket lifecycle, seal-tag construction, nesting, and identity binding behavior from the brief and fit-pack probing. Compare REPLY values against each case decoy_flag to distinguish success from failure when probing fit packs. Write /app/output/flags.json for the work set only.

Success criteria:
1. /app/output/flags.json exists as an ordinary file (not a symlink).
2. Top-level object has challenges array. Each element uses keys in order id then flag.
3. Challenge ids are sorted ascending and include every work directory name under /app/data/work/.
4. Serialized bytes match BRIEF formatting (2-space indent, ensure_ascii false, trailing newline).
5. Each work flag matches the vault release obtained under BRIEF rules for that case.
