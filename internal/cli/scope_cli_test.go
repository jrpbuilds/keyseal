package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end doctor/verify coverage for shared --scope/--profile/
// --identity-profile flags and scoped contract handling.

func TestDoctorAndVerifyScopeFlags(t *testing.T) {
	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	writeCLIFile(t, filepath.Join(repoRoot, "controller/website.enc.yaml"), "")
	appendAccessProfilesYAML(t, repoRoot, `access_profiles:
  app-server:
    include:
      - production/**
`)

	doctorOut, err := runRootCommand(t, repoRoot, "doctor", "--profile", "app-server", "--json")
	if err != nil {
		t.Fatalf("doctor --profile should pass: %v\n%s", err, doctorOut)
	}
	var doctorPayload struct {
		Summary struct {
			Fail     int `json:"fail"`
			Excluded int `json:"excluded"`
		} `json:"summary"`
		Scope struct {
			Mode    string `json:"mode"`
			Profile string `json:"profile"`
		} `json:"scope"`
	}
	if err := json.Unmarshal([]byte(doctorOut), &doctorPayload); err != nil {
		t.Fatalf("doctor json: %v\n%s", err, doctorOut)
	}
	if doctorPayload.Scope.Mode != "profile" || doctorPayload.Scope.Profile != "app-server" {
		t.Fatalf("unexpected doctor scope: %#v", doctorPayload.Scope)
	}
	if doctorPayload.Summary.Fail != 0 || doctorPayload.Summary.Excluded == 0 {
		t.Fatalf("unexpected doctor summary: %#v", doctorPayload.Summary)
	}

	verifyOut, err := runRootCommand(t, repoRoot, "verify", "--profile", "app-server", "--json")
	if err != nil {
		t.Fatalf("verify --profile should pass: %v\n%s", err, verifyOut)
	}
	var verifyPayload struct {
		Verified bool `json:"verified"`
		Summary  struct {
			Excluded int `json:"excluded"`
		} `json:"summary"`
		Scope struct {
			Mode string `json:"mode"`
		} `json:"scope"`
	}
	if err := json.Unmarshal([]byte(verifyOut), &verifyPayload); err != nil {
		t.Fatalf("verify json: %v\n%s", err, verifyOut)
	}
	if !verifyPayload.Verified || verifyPayload.Scope.Mode != "profile" || verifyPayload.Summary.Excluded == 0 {
		t.Fatalf("unexpected verify payload: %#v", verifyPayload)
	}
}

func TestDoctorRejectsConflictingScopeFlags(t *testing.T) {
	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	appendAccessProfilesYAML(t, repoRoot, `access_profiles:
  app-server:
    include:
      - production/**
`)

	output, err := runRootCommand(t, repoRoot, "doctor", "--scope", "production/**", "--profile", "app-server", "--json")
	if err == nil {
		t.Fatal("expected conflicting flags to fail")
	}
	if !strings.Contains(output, "scope selection") {
		t.Fatalf("expected scope selection failure, got %s", output)
	}
}

func TestVerifyExcludesOutsideContract(t *testing.T) {
	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	appendAccessProfilesYAML(t, repoRoot, `access_profiles:
  app-server:
    include:
      - production/**
contracts:
  controller-site:
    documents:
      - controller/website
    required:
      - SITE_KEY
`)

	output, err := runRootCommand(t, repoRoot, "verify", "--profile", "app-server", "--json")
	if err != nil {
		t.Fatalf("verify should pass with excluded contract: %v\n%s", err, output)
	}
	if !strings.Contains(output, `"status": "excluded"`) {
		t.Fatalf("expected excluded contract status in json, got %s", output)
	}
}

func TestVerifyMixedScopeContractFailsOnce(t *testing.T) {
	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	writeEncryptedFixture(t, repoRoot, "controller/website.enc.yaml")
	appendAccessProfilesYAML(t, repoRoot, `access_profiles:
  app-server:
    include:
      - production/**
contracts:
  mixed-role:
    documents:
      - production/platform/app
      - controller/website
    required:
      - APP_ENV
`)

	output, err := runRootCommand(t, repoRoot, "verify", "--profile", "app-server", "--json")
	if err == nil {
		t.Fatal("expected verify to fail on mixed-scope contract")
	}
	var payload struct {
		Verified bool `json:"verified"`
		Checks   []struct {
			Name    string `json:"name"`
			Status  string `json:"status"`
			Summary string `json:"summary"`
		} `json:"checks"`
	}
	if unmarshalErr := json.Unmarshal([]byte(output), &payload); unmarshalErr != nil {
		t.Fatalf("verify json: %v\n%s", unmarshalErr, output)
	}
	if payload.Verified {
		t.Fatal("expected verified=false")
	}
	mixedFails := 0
	for _, check := range payload.Checks {
		if check.Name == `contract "mixed-role"` && check.Status == "fail" {
			mixedFails++
			if !strings.Contains(check.Summary, "spans documents inside and outside the selected scope") {
				t.Fatalf("unexpected mixed summary: %#v", check)
			}
		}
	}
	if mixedFails != 1 {
		t.Fatalf("expected exactly one mixed contract fail, got %d in %#v", mixedFails, payload.Checks)
	}
}

func appendAccessProfilesYAML(t *testing.T, root, body string) {
	t.Helper()
	path := filepath.Join(root, "keyseal.yaml")
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if err := os.WriteFile(path, append(existing, []byte("\n"+body)...), 0o600); err != nil {
		t.Fatalf("append access profiles: %v", err)
	}
}
