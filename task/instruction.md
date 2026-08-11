Capture sealed RingVault flags for every challenge directory under /app/data/work/. The normative contract is /app/data/docs/BRIEF.md.

Drive the in-process lab package at /app/data/ringvault for each work case. Disclosed fit packs with expecteds are under /app/data/fit/. Induce framing, ticket issue, seal-tag, nesting, and generation-binding behavior from the brief and fit packs. Write /app/output/flags.json for the work set only.

Success criteria:
1. /app/output/flags.json exists as an ordinary file (not a symlink).
2. Top-level object has challenges array. Each element uses keys in order id then flag.
3. Challenge ids are sorted ascending and include every work directory name under /app/data/work/.
4. Serialized bytes match BRIEF formatting (2-space indent, ensure_ascii false, trailing newline).
5. Each work flag matches the vault release obtained under BRIEF rules for that case.
