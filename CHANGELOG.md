# Changelog

All notable changes to Keyseal will be documented in this file.

The format is intentionally lightweight and optimized for public release tags.

## v1.2.0 (2026-10-19)

Highlights:
- `keyseal render --profile <name>` executes every render defined by a profile in `keyseal.yaml`, resolving, decrypting, and pre-flighting all outputs before any write
- `--dry-run` with `--profile` validates the full plan and prints it without writing; it decrypts to fully validate inputs but never exposes values
- profile definitions are validated at config load: empty inputs, unknown formats, invalid modes, and duplicate output paths within a profile are all rejected
- `keyseal doctor` and `keyseal verify` now report per-profile configuration and input-resolvability problems as discrete checks
- new `keyseal clone` copies a secret document to a new name, encrypted for the recipients configured for the destination
- new `keyseal set`, `unset`, `generate`, and `import` change secret values without opening an editor; values come only from stdin, a file descriptor, or an env file
- every change is verified before it is saved, and the original file is left untouched if anything fails
- changes are refused if your SOPS rules would leave any secret value unencrypted
- `keyseal generate` creates strong random values as URL-safe base64, base64, or hex
- `keyseal unset` fails clearly when a key is not present instead of reporting success
- `--commit` now commits only the files the command changed, leaving your other staged work alone
- `keyseal add` and `keyseal edit` no longer write a temporary plaintext file while encrypting
- declarative secret contracts in `keyseal.yaml` can require, forbid, and constrain keys across one or more documents
- contracts support minimum length, regex, non-empty, equality, inequality, distinct values, and conditional requirements
- `keyseal doctor` reports malformed contract definitions and missing contract documents without decrypting values
- `keyseal verify` evaluates every contract against decrypted secrets and fails when any rule is violated
- new `keyseal validate <contract>` evaluates one named contract with optional machine-readable `--json` output
- contract failures report key names and rule kinds only, never secret values
- Keyseal now builds with Go 1.27.2
- dependency updates close the HTTP/2 findings from the vulnerability scan

## v1.1.0

Highlights:
- read-only decrypt paths now use the official SOPS Go decrypt library for `render`, `exec`, `doctor`, and `verify`
- production/deploy machines no longer need external `sops` or `age` binaries for read-only decrypt/render/exec/validation workflows; they still need Keyseal, encrypted files, and age private key material
- external SOPS CLI remains required for mutating workflows: `add`, `edit`, and `updatekeys`
- SOPS library compatibility warnings, such as older unencrypted comment warnings, are suppressed during `render` and `exec` but reported deliberately by `doctor`/`verify`
- documentation now distinguishes developer/admin machines from production/deploy machines and calls out that servers need the age key, not the age CLI

## v1.0.0

This release marks the first stable release of Keyseal.

It adds `keyseal verify`, a strict, non-mutating validation command designed for CI. `verify` reuses the same core checks as `doctor`, but fails on warnings as well as errors, making it suitable as a proper pipeline gate. `--json` output can also now be used more cleanly in automated workflows.

With this release, the v1 `keyseal.yaml` config contract and the `kind: env` secret document shape are now treated as stable. The documentation has also been tightened up to better distinguish production-ready workflows from starter templates that still need real secret values.

Highlights:
- `keyseal verify` adds a strict, non-mutating CI gate that reuses doctor checks but fails on warnings as well as failures
- Keyseal is now documented as production-ready for Barkway's Git-backed SOPS secret workflow
- the v1 `keyseal.yaml` config contract and `kind: env` secret document shape are treated as stable
- docs now distinguish production-ready tooling from starter templates that still require real secret values

## v0.3.0

Tightens up Keyseal's day-to-day secret handling, especially around empty placeholders, SOPS checks, and keeping encrypted files in sync when recipients change.

Highlights:
- SOPS-backed commands preflight the configured SOPS binary before mutating files, and `keyseal doctor` reports SOPS and age tool availability near the top of its output
- `keyseal updatekeys` now batch-syncs SOPS recipients for Keyseal-managed encrypted files from `.sops.yaml`, with placeholder/plaintext safety checks and optional explicit commits
- empty or whitespace-only `.enc.yaml` files are now treated as placeholder secrets so `render` and `exec` skip them when other requested secrets are usable, and fail clearly when every requested secret is still uninitialized
- `keyseal edit` now bootstraps placeholder secret files with an encrypted starter document before opening SOPS, making recovery from empty placeholder files a first-class workflow
- `keyseal doctor` now warns on empty placeholder secret files, continues to fail on non-empty plaintext content at encrypted paths, and includes regression coverage for the new secret-file classification behavior

## v0.2.0

Highlights:
- `keyseal add` now scaffolds via a secure temp file, runs `sops encrypt`, and atomically writes only encrypted output to the final `.enc.yaml` path by default
- `keyseal add` no longer exposes a plaintext scaffolding mode
- Keyseal now has first-class Git workflow support with `status`, `diff`, `history`, `commit`, and Git-based `rollback`
- `status` can now be scoped to one logical secret and `history` now supports a compact `--oneline` view
- `add`, `edit`, and `rollback` now support `--commit`, `-m/--message`, and config-driven `git.auto_commit`
- `sops.age_key_file` in `keyseal.yaml` is now passed through automatically to SOPS-backed commands, with `SOPS_AGE_KEY_FILE` remaining the higher-precedence override
- `keyseal doctor` now reports structured, actionable checks for config sanity, `.sops.yaml` readiness, placeholder recipients, SOPS availability, plaintext mistakes, decrypted schema validation, and JSON output for scripts
- `keyseal --version` and `keyseal version` now report stamped build metadata
- tagged `v*` GitHub releases now publish platform archives and SHA256 checksums
- Linux `.deb` and `.rpm` packaging now uses generated per-arch nfpm configs so release packaging does not depend on fragile env interpolation

## v0.1.0

Initial public release.

Highlights:
- Cobra-based CLI with `init`, `add`, `edit`, `render`, `exec`, and `doctor`
- SOPS subprocess integration for initial edit and decrypt flows
- deterministic logical-name to `.enc.yaml` mapping
- dotenv, JSON, and YAML render outputs
- doctor checks for config health, repo naming, schema validation, and plaintext starter-file detection
- GPL-3.0-only licensing

Known limitations:
- `keyseal add` creates a plaintext starter document until you encrypt it with `keyseal edit`
- only `kind: env` is supported
- rendering is limited to dotenv, JSON, and YAML
