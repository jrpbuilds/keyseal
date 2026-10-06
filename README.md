<p align="center">
  <img src="https://github.com/jrpbuilds/keyseal/wiki/keyseal-logo.webp" alt="Keyseal logo" width="320">
</p>

# Keyseal

[![CI](https://github.com/jrpbuilds/keyseal/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jrpbuilds/keyseal/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/jrpbuilds/keyseal)](https://github.com/jrpbuilds/keyseal/releases)
[![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](./LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.27%2B-00ADD8)](https://go.dev/)

> **Default flow:** `keyseal add` scaffolds and encrypts a new secret document immediately, without writing plaintext starter content to the final `.enc.yaml` path.

Keyseal is a small Go CLI that standardizes encrypted file workflows around `sops`, `age`, and Git. It was built to solve a real production problem: managing Git-backed SOPS secret workflows at scale.

It helps teams:

- keep encrypted secret files in a repository
- scaffold new secret documents
- open encrypted files in `sops`
- inspect Git status, diffs, and file history by logical name
- commit and roll back Keyseal-managed changes without staging the whole repo
- render decrypted values into runtime formats
- run commands with decrypted environment variables injected
- validate repository layout and config health
- enforce strict CI verification before release or deployment

Keyseal does not implement encryption itself, replace SOPS, run a server, expose an API, or behave like a hosted secrets platform.

Keyseal uses the official SOPS Go decrypt library for read-only decryption in render, exec, and validation paths. The external SOPS binary is still required for commands that create, edit, or rotate encrypted files.

## Why it exists

SOPS already solves encryption and editing well. Keyseal stays one layer above that and makes a repo-backed workflow more predictable:

- consistent file naming and layout
- Git-aware workflows around the encrypted files that already live in the repo
- small config with strong defaults
- repeatable render and exec flows
- clear validation for common mistakes

## Requirements

- Go 1.27+ to build the CLI
- age recipients configured in `.sops.yaml`

Developer/admin machines that run `keyseal add`, `keyseal edit`, `keyseal updatekeys`, or the mutation commands (`clone`, `set`, `unset`, `generate`, `import`) also need the external `sops` binary (3.9 or newer).

Production, CI, or deploy machines that only run `keyseal render`, `keyseal exec`, `keyseal doctor`, or `keyseal verify` need only:

- the `keyseal` binary
- the encrypted secrets files/repo
- age private key material, usually through `SOPS_AGE_KEY_FILE` or `sops.age_key_file`

They do not need the external `sops` binary or the external `age` binary. Servers need the age key, not the age CLI.

## Installation

Pre-built binaries and Linux packages are available on the [GitHub Releases](https://github.com/jrpbuilds/keyseal/releases) page. Each release includes tar.gz archives (Linux and macOS, amd64 and arm64), `.deb` and `.rpm` packages (Linux amd64 and arm64), and SHA256 checksums.

**Linux (Debian/Ubuntu):**

```bash
sudo dpkg -i keyseal_<version>_amd64.deb
```

**Linux (RHEL/Fedora/SUSE):**

```bash
sudo rpm -i keyseal-<version>-1.x86_64.rpm
```

**Other platforms:** extract the binary from the appropriate tar.gz archive and place it somewhere in your `PATH`.

## Quick start

```bash
make build
./bin/keyseal init
./bin/keyseal add production/platform/app --template laravel
./bin/keyseal edit production/platform/app
./bin/keyseal status
./bin/keyseal commit -m "Add production app secret"
./bin/keyseal render production/platform/app --stdout
./bin/keyseal doctor
```

For a fuller walkthrough, see the [Quick Start](https://github.com/jrpbuilds/keyseal/wiki/Quick-Start) guide and the [wiki](https://github.com/jrpbuilds/keyseal/wiki).

## Build

```bash
make tidy
make check
make build
./bin/keyseal --version
./bin/keyseal --help
```

## Command overview

- `keyseal init` bootstraps a repository layout, `keyseal.yaml`, and `.sops.yaml`
- `keyseal add <logical-name>` creates and encrypts a starter env secret document, with optional immediate Git commit support
- `keyseal edit <logical-name>` opens the target file with `sops`, bootstrapping empty placeholder files first when needed
- `keyseal clone <source> <destination>` copies a document to a new logical name, re-encrypted for the destination's `.sops.yaml` rule
- `keyseal set <logical-name> <KEY> --stdin|--fd N` sets one value read from stdin or a file descriptor
- `keyseal unset <logical-name> <KEY>...` removes keys, failing without changes if any key is absent
- `keyseal generate <logical-name> <KEY>...` sets keys to cryptographically secure random values
- `keyseal import <logical-name> --from-env-file <path> --keys <KEY,...>` copies selected values from a dotenv file
- `keyseal updatekeys [logical-name...]` syncs SOPS recipients from `.sops.yaml`, with optional explicit Git commit support
- `keyseal status [logical-name]` shows Git status for Keyseal-managed files
- `keyseal diff <logical-name>` shows `git diff` for one secret file
- `keyseal history <logical-name>` shows file-scoped Git history for one secret file
- `keyseal commit` stages current Keyseal-managed changes and creates a Git commit
- `keyseal rollback <logical-name> --to <commit>` restores one secret file from Git history
- `keyseal render <logical-name...>` decrypts, merges, and renders secret values, skipping empty placeholder files
- `keyseal exec <logical-name...> -- <command...>` runs a child process with merged env vars
- `keyseal doctor` validates config sanity, SOPS CLI availability, age key/deployment context, `.sops.yaml` readiness, and common mistakes
- `keyseal verify` runs strict CI checks and fails on any doctor warning or failure
- `keyseal version` reports version, commit, and build date metadata

Detailed flags, examples, and behavior notes live in the [Command Reference](https://github.com/jrpbuilds/keyseal/wiki/Command-Reference) and [wiki](https://github.com/jrpbuilds/keyseal/wiki).

## What Keyseal is not

- not a crypto implementation
- not a Vault replacement
- not a secret hosting service
- not a daemon or web UI
- not a Kubernetes controller

## Usage

```bash
keyseal add production/platform/app --template laravel
keyseal edit production/platform/app
keyseal clone production/platform/app production/platform/app-next
printf '%s' "$STRIPE_SECRET_KEY" | keyseal set production/platform/app-next STRIPE_SECRET_KEY --stdin
keyseal unset production/platform/app-next TWILIO_TOKEN
keyseal generate production/platform/app-next APP_SIGNING_KEY --bytes 32
keyseal import production/platform/app-next --from-env-file ./intake.env --keys STRIPE_SECRET_KEY,STRIPE_PUBLIC_KEY -m "Prepare app candidate"
keyseal updatekeys production/platform/app --yes
keyseal status production/platform/app
keyseal history production/platform/app --oneline
keyseal commit -m "Update production app secret"
keyseal render production/platform/app --stdout --format json
keyseal render --profile production
keyseal render --profile production --dry-run
keyseal exec production/platform/app -- php artisan migrate
keyseal rollback production/platform/app --to <commit> --dry-run
keyseal doctor
keyseal verify
```

Key workflow details:

- `-m, --message` implies commit on mutating commands
- `--commit` commits only the files the command changed; anything else you have staged stays staged
- `git.auto_commit` is off by default
- `set` reads values only from stdin or a file descriptor, never from arguments; on a terminal it prompts without echo
- each `clone`, `set`, `unset`, `generate`, or `import` run is one transaction: the document is re-encrypted with the `.sops.yaml` rule for its path, decrypted again to verify it, and only then replaces the original; on any failure the original is left untouched
- mutations refuse to write if the `.sops.yaml` rule for the path would leave any secret value unencrypted, for example an `encrypted_regex` that does not cover `values`
- because mutations re-encrypt, they also apply any recipient changes in `.sops.yaml` that `updatekeys` has not yet synced
- mutation commands print key names and actions only, never values
- `sops.age_key_file` is used as the default age key path unless `SOPS_AGE_KEY_FILE` is already set
- read-only decrypt paths use the SOPS Go library and do not require external `sops` or `age` binaries
- mutating commands check the configured `sops.binary` before creating, editing, or rotating encrypted files
- `updatekeys` uses `.sops.yaml` as the recipient source of truth and does not rotate secret values or data encryption keys
- `keyseal commit` stages only Keyseal-managed files, not the whole repo
- `rollback` restores the encrypted file from Git history; `--dry-run` previews safely
- `profiles` in `keyseal.yaml` group render definitions; all profiles are validated on every config load, so a malformed profile blocks any command until fixed
- `render --profile --dry-run` decrypts and fully validates inputs (age key material required) but writes nothing and prints only the plan

For exact command behavior and more examples, see the [Command Reference](https://github.com/jrpbuilds/keyseal/wiki/Command-Reference), [Configuration Reference](https://github.com/jrpbuilds/keyseal/wiki/Configuration-Reference), and [Troubleshooting](https://github.com/jrpbuilds/keyseal/wiki/Troubleshooting) wiki pages.

## Version reporting

```bash
keyseal --version
keyseal version
keyseal version --short
```

Release builds stamp version, commit, and build date metadata via Go linker flags. Local builds default to `dev`, `unknown`, and `unknown` unless you pass `VERSION`, `COMMIT`, and `DATE`. When Git metadata is available, local builds use the latest `v*` tag and the short current commit.

## Release artifacts

```bash
make dist VERSION=v1.0.0 COMMIT=$(git rev-parse --short HEAD) DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
```

`make dist` builds tar.gz archives, `.deb` and `.rpm` packages for Linux (amd64, arm64), and a single SHA256 checksums file covering all artifacts to `dist/`. Linux packages require [nfpm](https://nfpm.goreleaser.com/install/) to be installed.

## Development

```bash
make fmt
make check
make test
make build
```

Contributor-oriented detail is available in the [Contributing](https://github.com/jrpbuilds/keyseal/wiki/Contributing) wiki page.

## Origin

Keyseal was born out of a real production need: managing encrypted secret files safely and predictably with SOPS-compatible encryption, age keys, and Git. It is a small, focused tool for teams that want Git-backed secret workflows without the overhead of a hosted platform.

## Licensing

This package is licensed under `GPL-3.0-only` (GNU General Public License v3.0 only).

If you distribute this package, modifications, or derivative works, review the GPLv3 obligations first to make sure your usage and distribution model remain compliant.

See [LICENSE](./LICENSE) for the full license text.
