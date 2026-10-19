package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/config"
)

func writeContractsConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyseal.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadContractsHappyPath(t *testing.T) {
	path := writeContractsConfig(t, `version: 1
repository:
  root: .
contracts:
  production-app:
    documents: [production/app]
    required: [APP_KEY]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	def, ok := cfg.Contracts["production-app"]
	if !ok {
		t.Fatal("expected production-app contract")
	}
	if len(def.Required) != 1 || def.Required[0] != "APP_KEY" {
		t.Fatalf("unexpected contract: %#v", def)
	}
}

func TestLoadRejectsMalformedContracts(t *testing.T) {
	path := writeContractsConfig(t, `version: 1
contracts:
  app:
    documents: [production/app]
    min_lenght: 32
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected Load to reject unknown contract field")
	} else if !strings.Contains(err.Error(), "min_lenght") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadLenientKeepsContractProblems(t *testing.T) {
	path := writeContractsConfig(t, `version: 1
contracts:
  app:
    documents: [production/app]
    rules:
      - key: APP_KEY
        matches: "("
`)
	cfg, err := config.LoadLenient(path)
	if err != nil {
		t.Fatalf("LoadLenient returned error: %v", err)
	}
	if len(cfg.ContractProblems) == 0 {
		t.Fatal("expected contract problems to be retained")
	}
	if _, ok := cfg.Contracts["app"]; ok {
		t.Fatal("malformed contract must not appear in Contracts")
	}
}

func TestLoadOmitsContracts(t *testing.T) {
	path := writeContractsConfig(t, `version: 1
repository:
  root: .
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Contracts == nil || len(cfg.Contracts) != 0 {
		t.Fatalf("expected empty contracts map, got %#v", cfg.Contracts)
	}
}

func TestLoadUnknownKeysOutsideContractsStillIgnored(t *testing.T) {
	path := writeContractsConfig(t, `version: 1
repository:
  root: .
unknown_top_level_key: ignored
contracts:
  app:
    documents: [production/app]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if _, ok := cfg.Contracts["app"]; !ok {
		t.Fatal("expected app contract")
	}
}
