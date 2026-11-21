# Changelog

All notable changes to Keyseal will be documented in this file.

The format is intentionally lightweight and optimized for public release tags.

## Unreleased

## v1.2.0

This release makes Keyseal easier to drive from automation and safer to use in mixed repositories: selected-key render, cleaner exec environments, scoped commits, secret contracts, and repository version gates.

### Render and exec

- `keyseal render --profile` runs every render defined in `keyseal.yaml`, with `--dry-run` to validate the plan without writing
- `keyseal render --select` emits only named keys after merge; `--require-all` fails closed when any selected key is missing
- Stable `render` exit codes distinguish missing keys, decrypt failures, and invalid documents
- `keyseal exec --clean-env` starts the child from an empty environment; `--keep-env` copies only the named parent variables

### Git and mutations

- `keyseal commit` accepts logical names to stage only those documents, and `--dry-run` lists the exact paths that would be staged
- Named commits refuse missing, unchanged, ambiguous, or invalid names before touching Git
- New `clone`, `set`, `unset`, `generate`, and `import` change secrets without an editor; values come from stdin, a file descriptor, or an env file
- Mutations verify before save, leave the original untouched on failure, and refuse writes that would leave secret values unencrypted
- `--commit` on mutating commands commits only the files that command changed

### Validation and compatibility

- Declarative `contracts` in `keyseal.yaml`, plus `keyseal validate`, enforce required and forbidden keys and related rules without printing values
- `keyseal inspect`, `compare`, and `diff --semantic` report key state without showing secret values
- `doctor` and `verify` can scope checks with `--scope`, `--profile`, or `--identity-profile`, using `access_profiles` for role-aware include/exclude globs
- Repositories can declare `requirements.keyseal`; `keyseal version --check` validates a constraint without loading the repo

### Toolchain

- Builds with Go 1.27.3
- Dependency updates close the HTTP/2 findings from the vulnerability scan

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
