# OpenMedic — Security and Safety Requirements

## Threat model

OpenMedic processes CI logs, source repositories, workflow metadata, and potentially AI-generated suggestions. These inputs may contain secrets, malicious instructions, malicious patches, or misleading evidence. A CI failure does not grant OpenMedic authority to execute arbitrary code or access production systems.

## Mandatory rules

1. **Untrusted inputs:** Treat logs, code, filenames, commit messages, workflow names, issue text, and model responses as untrusted data. Prompt injection in logs must not change tool permissions or safety policy.
2. **Secret handling:** Never commit tokens or keys. Read credentials from environment variables or a secret manager. Redact likely tokens/passwords from logs and reports. Do not send secrets to model providers.
3. **Least privilege:** GitHub ingestion starts read-only. Comments, branch creation, and PRs require separately configured write permissions.
4. **No arbitrary command execution:** Model output may propose a patch, but must not directly execute shell commands. Use allowlisted checks and explicit application policy.
5. **Isolation:** Apply patches in a disposable worktree/container. Prefer non-root execution, no privileged host mounts, no host Docker socket, no SSH agent forwarding, and no production credentials in the sandbox.
6. **Resource limits:** Enforce wall-clock timeout and, where available, CPU, memory, process, disk, and network limits. Clean up on timeout or crash.
7. **Diff review:** Show patch/diff before application. Reject modifications that remove tests, weaken assertions, disable security checks, or hide failures unless a human explicitly reviews a documented exception.
8. **Human review:** Required for high-risk changes, ambiguous diagnosis, weak evidence, or incomplete validation.
9. **Validation integrity:** No missing/skipped/failed/timed-out check can be counted as passing. Bind validation to the exact candidate patch.
10. **Auditability:** Record decisions, state transitions, patch identity, commands/check IDs, exit codes, and validation results without recording credentials.
11. **No auto-merge/deploy:** OpenMedic may create a reviewable PR only after validation and with explicit configuration. It must never merge or deploy automatically.
12. **Safe defaults:** Diagnosis/report-only by default. Repair application and GitHub write operations are explicit opt-ins.

## Security tests

- Secret redaction in common token formats.
- Prompt-injection text inside logs does not change safety policy.
- Provider output containing shell commands is treated as data, not executed.
- Patch attempts to delete tests or disable checks are rejected.
- Non-zero exit, timeout, missing check, or stale patch cannot result in `recovered`.
- GitHub permission failure does not silently fall back to broader credentials.
- Temporary workspaces and credentials are cleaned up after success, failure, timeout, or cancellation.

## Disclosure

This document is a baseline, not a claim of a completed security audit. Document any controls that are not yet implemented and do not advertise the tool as secure or production-ready without evidence.
