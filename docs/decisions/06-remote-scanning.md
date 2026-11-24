# 06. Scanning a repository URL

## What was built
`guardian scan <url | owner/repo | path> [--ref REF] [--keep/--no-keep]`. Remote targets are
cloned into `~/.guardian/workspaces/<hash>/<repo>` and scanned like local folders. With no
target in a terminal, Guardian prompts. Verified live on OWASP NodeGoat (17 s, 342 findings).

## Decisions

### HTTPS only, shallow, no submodules, no hooks
Rejected up front: `http://`, `ssh://`, `git@`, `file://`, `ext::` and URLs with embedded
credentials. `core.symlinks=false` so symlinks become plain files instead of pointers outside the
clone. Reason: a clone is the riskiest step; `ext::` and `file://` can execute commands or read
local files. Alternative: allow SSH (private repos work, but credentials and agent forwarding
enter the picture), or download release tarballs (no git history, so no change analysis).

### Override of the blanket protocol ban
The runner sets `protocol.allow=never` for hardening, which also blocked HTTPS clones. The clone
command re-enables only `protocol.https.allow=always` via `-c`.

### Deterministic workspace path
The same repository always lands in the same directory, so `guardian history` groups its scans
and an incremental cache can be reused. Alternative: a temp directory per scan (clean, but
history and `explain` lose the files).

### Keep the clone by default
`guardian explain` and `guardian code` read files later, and reports need snippets. `--no-keep`
deletes the clone after the scan, and reports are built before deletion.

### GitHub shorthand
`owner/repo` is expanded to a GitHub HTTPS URL. Side effect: a single word containing a slash
(like `and/or`) in the shell is read as a repo. Harmless, but noisy.
