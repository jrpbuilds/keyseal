package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/buildinfo"
	"github.com/jrpbuilds/keyseal/internal/config"
)

func TestLoadAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyseal.yaml")
	body := []byte("version: 1\nrepository:\n  root: .\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Repository.EncryptedExtension != ".enc.yaml" {
		t.Fatalf("expected default encrypted extension, got %q", cfg.Repository.EncryptedExtension)
	}
	if cfg.Defaults.OutputFormat != "dotenv" {
		t.Fatalf("expected default output format, got %q", cfg.Defaults.OutputFormat)
	}
	if cfg.Git.AutoCommit {
		t.Fatal("expected git.auto_commit to default to false")
	}
	if cfg.SOPS.AgeBinary != "age" {
		t.Fatalf("expected default age binary, got %q", cfg.SOPS.AgeBinary)
	}
	if cfg.Validation.KeyPattern != "^[A-Z0-9_]+$" {
		t.Fatalf("expected default key pattern, got %q", cfg.Validation.KeyPattern)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyseal.yaml")
	body := []byte("version: 1\ndefaults:\n  file_mode: not-a-mode\nvalidation:\n  key_pattern: \"[\"\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := config.Load(path); err == nil {
		t.Fatal("expected invalid config to fail")
	}
}

func TestLoadRejectsMalformedKeysealRequirement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyseal.yaml")
	body := []byte("version: 1\nrepository:\n  root: .\nrequirements:\n  keyseal: \">>>>\"\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := config.Load(path); err == nil {
		t.Fatal("expected malformed requirements.keyseal to fail")
	}
}

func TestLoadEnforcesKeysealRequirement(t *testing.T) {
	orig := buildinfo.Version
	buildinfo.Version = "v0.2.0"
	t.Cleanup(func() { buildinfo.Version = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "keyseal.yaml")
	body := []byte("version: 1\nrepository:\n  root: .\nrequirements:\n  keyseal: \">=1.1.0\"\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := config.Load(path); err == nil {
		t.Fatal("expected Load to fail closed on unmet requirements.keyseal")
	} else if !strings.Contains(err.Error(), "v0.2.0") || !strings.Contains(err.Error(), ">=1.1.0") {
		t.Fatalf("error should name running and required versions, got: %v", err)
	}

	cfg, err := config.LoadLenient(path)
	if err != nil {
		t.Fatalf("LoadLenient should not enforce binary requirement: %v", err)
	}
	if err := cfg.CheckKeysealRequirement(buildinfo.DisplayVersion()); err == nil {
		t.Fatal("expected CheckKeysealRequirement to fail for v0.2.0 vs >=1.1.0")
	}

	buildinfo.Version = "v1.1.0"
	if _, err := config.Load(path); err != nil {
		t.Fatalf("Load should succeed when binary satisfies requirement: %v", err)
	}
}

func TestLoadReportsKeysealRequirementBeforeProfileErrors(t *testing.T) {
	orig := buildinfo.Version
	buildinfo.Version = "v0.2.0"
	t.Cleanup(func() { buildinfo.Version = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "keyseal.yaml")
	body := []byte(`version: 1
repository:
  root: .
requirements:
  keyseal: ">=1.1.0"
profiles:
  broken:
    renders:
      - name: ""
        inputs: []
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected Load to fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "v0.2.0") || !strings.Contains(msg, ">=1.1.0") {
		t.Fatalf("expected unmet requirements.keyseal to surface first, got: %v", err)
	}
	if strings.Contains(msg, "render name") || strings.Contains(msg, "profiles.broken") {
		t.Fatalf("profile error should not mask version requirement, got: %v", err)
	}
}

func TestValidateEnforcesKeysealRequirement(t *testing.T) {
	orig := buildinfo.Version
	buildinfo.Version = "v0.2.0"
	t.Cleanup(func() { buildinfo.Version = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "keyseal.yaml")
	body := []byte("version: 1\nrepository:\n  root: .\nrequirements:\n  keyseal: \">=1.1.0\"\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.LoadLenient(path)
	if err != nil {
		t.Fatalf("LoadLenient returned error: %v", err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Validate to fail closed on unmet requirements.keyseal")
	} else if !strings.Contains(err.Error(), "v0.2.0") || !strings.Contains(err.Error(), ">=1.1.0") {
		t.Fatalf("Validate error should name running and required versions, got: %v", err)
	}
}

func TestLoadRejectsWhitespaceOnlyKeysealRequirement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyseal.yaml")
	body := []byte("version: 1\nrepository:\n  root: .\nrequirements:\n  keyseal: \"   \"\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := config.Load(path); err == nil {
		t.Fatal("expected Load to reject whitespace-only requirements.keyseal")
	} else if !strings.Contains(err.Error(), "whitespace-only") {
		t.Fatalf("unexpected Load error: %v", err)
	}
	if _, err := config.LoadLenient(path); err == nil {
		t.Fatal("expected LoadLenient to reject whitespace-only requirements.keyseal")
	} else if !strings.Contains(err.Error(), "whitespace-only") {
		t.Fatalf("unexpected LoadLenient error: %v", err)
	}
}
