package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/config"
)

// access_profiles load, match, and secret-safe rejection coverage.

const (
	accessTestPublicRecipient = "age1xlp99sh4c9dheuskt900y83mdcxdhjp0zhejf2l4lkh6fdzl0dsqsx4yrx"
	accessTestSecretKey       = "AGE-SECRET-KEY-1640MNDQ274MATFJR6D6R6GFW3FUDJLDUAM84TXRM9L70FUCEXV0QMEH0CE"
)

func writeAccessTestConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyseal.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadAccessProfilesValid(t *testing.T) {
	path := writeAccessTestConfig(t, `version: 1
repository:
  root: .
access_profiles:
  app-server:
    include:
      - production/app
      - production/monitoring
    exclude:
      - controller/**
  controller:
    include:
      - controller/**
    recipients:
      - `+accessTestPublicRecipient+`
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	app := cfg.AccessProfiles["app-server"]
	if len(app.Include) != 2 || app.Include[0] != "production/app" {
		t.Fatalf("unexpected app-server include: %#v", app.Include)
	}
	ok, err := app.Matches("production/app")
	if err != nil || !ok {
		t.Fatalf("expected production/app included, ok=%v err=%v", ok, err)
	}
	ok, err = app.Matches("controller/website")
	if err != nil || ok {
		t.Fatalf("expected controller/website excluded, ok=%v err=%v", ok, err)
	}
	ctrl := cfg.AccessProfiles["controller"]
	if len(ctrl.Recipients) != 1 || ctrl.Recipients[0] != accessTestPublicRecipient {
		t.Fatalf("unexpected controller recipients: %#v", ctrl.Recipients)
	}
}

func TestLoadRejectsPrivateIdentityMaterialWithoutEcho(t *testing.T) {
	path := writeAccessTestConfig(t, `version: 1
repository:
  root: .
access_profiles:
  bad:
    include:
      - production/**
    recipients:
      - `+accessTestSecretKey+`
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected Load to reject private identity material")
	}
	msg := err.Error()
	if !strings.Contains(msg, "private identity material is not allowed") {
		t.Fatalf("expected fixed private-material message, got %q", msg)
	}
	if strings.Contains(msg, accessTestSecretKey) || strings.Contains(msg, "AGE-SECRET-KEY-") {
		t.Fatalf("error must not echo secret key material: %q", msg)
	}

	cfg, err := config.LoadLenient(path)
	if err != nil {
		t.Fatalf("LoadLenient should keep problems: %v", err)
	}
	if len(cfg.AccessProfileProblems) == 0 {
		t.Fatal("expected AccessProfileProblems from LoadLenient")
	}
	problem := cfg.AccessProfileProblems[0].Error()
	if strings.Contains(problem, accessTestSecretKey) {
		t.Fatalf("problem must not echo secret key material: %q", problem)
	}
}

func TestLoadRejectsUnknownAccessProfileField(t *testing.T) {
	path := writeAccessTestConfig(t, `version: 1
repository:
  root: .
access_profiles:
  bad:
    include:
      - production/**
    private_key_file: /tmp/keys.txt
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected unknown field to fail")
	}
	if !strings.Contains(err.Error(), `unknown field "private_key_file"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsEmptyAccessProfile(t *testing.T) {
	path := writeAccessTestConfig(t, `version: 1
repository:
  root: .
access_profiles:
  bad: {}
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected empty profile to fail")
	}
	if !strings.Contains(err.Error(), "include or exclude is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAccessProfileExcludeWins(t *testing.T) {
	profile := config.AccessProfile{
		Include: []string{"production/**"},
		Exclude: []string{"production/controller/**"},
	}
	ok, err := profile.Matches("production/app")
	if err != nil || !ok {
		t.Fatalf("expected production/app included, ok=%v err=%v", ok, err)
	}
	ok, err = profile.Matches("production/controller/website")
	if err != nil || ok {
		t.Fatalf("expected production/controller/website excluded, ok=%v err=%v", ok, err)
	}
}

func TestAccessProfileEmptyIncludeMeansAllMinusExclude(t *testing.T) {
	profile := config.AccessProfile{
		Exclude: []string{"controller/**"},
	}
	ok, err := profile.Matches("production/app")
	if err != nil || !ok {
		t.Fatalf("expected production/app included, ok=%v err=%v", ok, err)
	}
	ok, err = profile.Matches("controller/website")
	if err != nil || ok {
		t.Fatalf("expected controller/website excluded, ok=%v err=%v", ok, err)
	}
}
