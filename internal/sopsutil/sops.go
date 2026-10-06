// Package sopsutil contains the small SOPS integration layer used by Keyseal.
//
// Read-only decrypt operations use the official SOPS Go library so production
// hosts do not need the external sops binary. Mutating operations still shell
// out to the SOPS CLI because encryption, editing, and recipient updates are
// intentionally delegated to SOPS itself.
package sopsutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/toolcheck"
)

// ageKeyEnvVar is the SOPS-supported environment variable for age identities.
const ageKeyEnvVar = "SOPS_AGE_KEY_FILE"

// ErrBinaryNotFound is returned when the configured sops binary cannot be found.
var ErrBinaryNotFound = errors.New("sops binary not found")

// LookPath resolves the configured sops binary in PATH.
func LookPath(binary string) (string, error) {
	path, err := toolcheck.Resolve(binary)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrBinaryNotFound, binary)
	}
	return path, nil
}

// EditFile launches `sops <file>` attached to the current terminal.
func EditFile(binary, ageKeyFile, path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("stat encrypted file: %w", err)
	}
	if _, err := LookPath(binary); err != nil {
		return err
	}
	cmd := exec.Command(binary, path)
	cmd.Env = commandEnv(ageKeyFile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run sops editor for %s: %w", path, err)
	}
	return nil
}

// Version returns the first non-empty line from `sops --version`.
func Version(binary, ageKeyFile string) (string, error) {
	result, err := toolcheck.Probe(binary, commandEnv(ageKeyFile), "--version")
	if err != nil {
		return "", err
	}
	return result.Version, nil
}

// EncryptFile encrypts plaintext by piping it to
// `sops encrypt --filename-override <target>` on stdin.
//
// Plaintext never touches disk and never appears in process arguments. The
// filename override makes SOPS select the .sops.yaml creation rule for the
// target path. The caller owns the final write so plaintext stays out of the
// destination `.enc.yaml` file entirely.
func EncryptFile(binary, ageKeyFile string, plaintext []byte, filenameOverride string) ([]byte, error) {
	if _, err := LookPath(binary); err != nil {
		return nil, err
	}

	cmd := exec.Command(binary, "encrypt", "--filename-override", filenameOverride)
	cmd.Env = commandEnv(ageKeyFile)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdin = bytes.NewReader(plaintext)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("encrypt %s with sops: %s", filepath.Base(filenameOverride), sanitizeOutput(stderr.Bytes(), stdout.Bytes()))
	}
	return stdout.Bytes(), nil
}

// commandEnv preserves an explicit shell override and otherwise injects the
// configured age key file so CLI-backed SOPS commands honor keyseal.yaml.
func commandEnv(ageKeyFile string) []string {
	env := os.Environ()
	// SOPS_AGE_KEY_FILE is the highest-precedence operator override. Keeping it
	// intact lets CI or one-off shells choose a key without editing keyseal.yaml.
	if os.Getenv(ageKeyEnvVar) != "" || strings.TrimSpace(ageKeyFile) == "" {
		return env
	}
	return append(env, ageKeyEnvVar+"="+ageKeyFile)
}

// sanitizeOutput returns a short subprocess error without risking a long dump
// of command output into Keyseal errors.
func sanitizeOutput(primary, fallback []byte) string {
	text := strings.TrimSpace(string(primary))
	if text == "" {
		text = strings.TrimSpace(string(fallback))
	}
	if text == "" {
		return "sops command failed"
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 3 {
		lines = lines[:3]
	}
	return strings.Join(lines, "; ")
}
