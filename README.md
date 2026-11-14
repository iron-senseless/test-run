# test-run — public isolated CI

This repository is a **public, unprivileged CI execution sandbox**. Its first consumer is the private [GhostMyFresh](https://github.com/iron-senseless/GhostMyFresh) project, but the sandbox is deliberately independent of any private repository.

## Security boundary

- **Never** check out, clone, or mirror the private GhostMyFresh repository directly inside a public job. Do not add private repository access tokens, deploy keys, Actions secrets, or credentials.
- **Never** commit or upload proprietary firmware, extracted Samsung binaries, Watch7 personal identifiers (serial, IMEI, EID, eSIM), device backups, access keys, unpublished vulnerability materials, private logs, or unrestricted Git history.
- Public CI inputs are a **separately reviewed, explicitly allowlisted subset** of source and synthetic fixtures. Copy with a fresh history, not a fork or mirror of the private repo. Review filenames **and contents** before each transfer; automation may stage candidates but must not publish unreviewed material.
- All commits, PR diffs, job logs, artifacts, and caches are potentially public. Do not print secrets. Nothing classified as LIVE/BINARY/private can be promoted to public just to enable CI.
- Use only standard GitHub-hosted runners. No self-hosted machines, privileged actions, or `pull_request_target`. Keep the job token read-only.
- Treat outputs as **public synthetic/host CI evidence only**. They do not validate original Samsung firmware or demonstrate device exploitation. Link relevant public run, source revision and exact published input SHA in the private project's documentation/PR.
- For jobs that cannot be safely sanitized, use the owner's laptop or a private runner instead.

## How it works

1. Review the proposed input in the **private** source project.
2. Create a separate, sanitized copy under `jobs/` and related tests under `tests/` in this **public** repo. Never `git push --mirror` or copy `.git`.
3. Open a PR to `main`, let the public CI run, and inspect the job output.
4. Record the public run URL, its commit SHA, and the input-to-source provenance in the private project. Keep strategic decisions and research history there.

The workflow currently runs Python syntax checking and `unittest` on public, self-contained test inputs only. It is an initial **infrastructure smoke test**, not a migration of GhostMyFresh tests. Add specialized public jobs only after a separate exposure review.

## Billing

Standard GitHub-hosted Actions runners are free for public repositories, subject to GitHub's abuse/usage policies. Larger runners and certain storage use can still incur charges.
