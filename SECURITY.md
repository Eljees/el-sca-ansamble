# Security Policy

## Supported versions

The repository follows loose semver.  Only the `main` branch and the most
recent tagged release receive security fixes.  Older releases may be
patched on a best-effort basis if the underlying upstream scanner
(Trivy / Grype / cve-bin-tool / Syft) ships a fix that is mechanically
applicable.

## Reporting a vulnerability

**Do not** open a public GitHub Issue.

Please contact the maintainer directly via the email on the repository
profile, or via a private channel (Telegram / Signal) if you already have
one.  Include:

- A description of the issue and the path of the affected file(s).
- A minimal reproduction (input + expected vs. actual behaviour).
- The output of `python -m resilient_updates.cli healthcheck`.
- Any logs that demonstrate the impact, with secrets redacted.

We aim to acknowledge reports within **3 working days** and to ship a fix
or mitigation within **30 days** for high-severity issues, longer for
issues that require upstream coordination.

## Threat model and what we protect against

This project is a containerised orchestrator around well-known SCA
scanners.  Concretely we defend against:

- **Compromised CVE feed**: any upstream may serve a tampered DB.
  Mitigations: SHA-256 + age validation on Grype DB, `db_policy`
  (`strict` / `degraded-ok` / `lkg-ok`) and `last_known_good` rollback
  for cve-bin-tool, signature/checksum support for Trivy where upstream
  supports it.
- **Network egress hijack**: outbound traffic goes through the optional
  sidecar chain `tinyproxy → xray → upstream`.  See
  `docs/network-design.md`.
- **Air-gapped runs**: `--profile airgap` removes any updater service
  from the compose graph; scanners use only local volumes.

What we **do not** claim to defend against:

- Compromised host kernel or Docker daemon.
- Code-execution vulnerabilities in upstream scanners themselves (we
  surface their findings; we are not their security boundary).
- Side-channel attacks against the WireGuard endpoint when the optional
  `vpn` profile is used.

## Secret handling

- NVD API keys and registry tokens **must** live in `.env.local`
  (gitignored), never in `.env` (which itself is gitignored but is
  routinely synced through cloud-drive folders).
- The audit at `docs/audit/10-defects.md` section 1 documents the
  historical incident where keys were synced to Yandex Disk; rotate
  any key that may have been exposed that way.

## Acknowledgements

We try to credit reporters in the relevant `CHANGELOG.md` entry unless
they ask to stay anonymous.
