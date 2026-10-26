package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/buildinfo"
	"github.com/jrpbuilds/keyseal/internal/doctor"
)

// TestVerifyPassesOnCleanRepository verifies strict verification succeeds when
// doctor reports no warnings or failures.
func TestVerifyPassesOnCleanRepository(t *testing.T) {
	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")

	output, err := runRootCommand(t, repoRoot, "verify")
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	if !strings.Contains(output, "verify passed:") {
		t.Fatalf("expected verify pass output, got %q", output)
	}
	if strings.Contains(output, "[OK]") {
		t.Fatalf("expected concise output without OK checks, got %q", output)
	}
}

// TestVerifyFailsOnWarning verifies warnings are strict CI failures even when
// doctor would still exit successfully.
func TestVerifyFailsOnWarning(t *testing.T) {
	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	writeCLIFile(t, filepath.Join(repoRoot, "production/platform/empty.enc.yaml"), " \n")

	doctorOutput, doctorErr := runRootCommand(t, repoRoot, "doctor")
	if doctorErr != nil {
		t.Fatalf("doctor should not fail on warning-only repo: %v", doctorErr)
	}
	if !strings.Contains(doctorOutput, "[WARN]") {
		t.Fatalf("expected doctor warning output, got %q", doctorOutput)
	}

	verifyOutput, verifyErr := runRootCommand(t, repoRoot, "verify")
	if verifyErr == nil {
		t.Fatal("expected verify to fail on warning")
	}
	if !strings.Contains(verifyOutput, "verify failed: 0 failure(s), 1 warning(s)") {
		t.Fatalf("expected strict warning failure, got %q", verifyOutput)
	}
	if strings.Contains(verifyOutput, "[OK]") {
		t.Fatalf("expected verify output to omit OK checks, got %q", verifyOutput)
	}
}

// TestVerifyFailsOnFailure verifies normal doctor failures also fail strict
// verification.
func TestVerifyFailsOnFailure(t *testing.T) {
	repoRoot := t.TempDir()

	output, err := runRootCommand(t, repoRoot, "verify")
	if err == nil {
		t.Fatal("expected verify to fail when keyseal.yaml is missing")
	}
	if !strings.Contains(output, "verify failed:") || !strings.Contains(output, "[FAIL] keyseal.yaml") {
		t.Fatalf("unexpected verify failure output: %q", output)
	}
}

// TestVerifyJSONOutput verifies the machine-readable verdict and strict exit
// behavior.
func TestVerifyJSONOutput(t *testing.T) {
	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	writeCLIFile(t, filepath.Join(repoRoot, "production/platform/empty.enc.yaml"), " \n")

	output, err := runRootCommand(t, repoRoot, "verify", "--json")
	if err == nil {
		t.Fatal("expected verify --json to fail on warning")
	}

	var payload struct {
		Verified bool `json:"verified"`
		Summary  struct {
			Warn int `json:"warn"`
		} `json:"summary"`
		Checks []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if unmarshalErr := json.Unmarshal([]byte(output), &payload); unmarshalErr != nil {
		t.Fatalf("Unmarshal returned error: %v\noutput=%s", unmarshalErr, output)
	}
	if payload.Verified {
		t.Fatalf("expected verified=false, got %#v", payload)
	}
	if payload.Summary.Warn == 0 {
		t.Fatalf("expected warning count, got %#v", payload)
	}
	if len(payload.Checks) == 0 {
		t.Fatalf("expected checks in verify json, got %#v", payload)
	}
}

func TestVerifyFailsOnKeysealVersionRequirement(t *testing.T) {
	orig := buildinfo.Version
	buildinfo.Version = "v0.2.0"
	t.Cleanup(func() { buildinfo.Version = orig })

	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")

	cfgPath := filepath.Join(repoRoot, "keyseal.yaml")
	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	body = append(body, []byte("\nrequirements:\n  keyseal: \">=1.1.0\"\n")...)
	if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	output, runErr := runRootCommand(t, repoRoot, "verify", "--json")
	if runErr == nil {
		t.Fatal("expected verify to fail when Keyseal binary is too old")
	}

	var payload struct {
		Verified bool `json:"verified"`
		Checks   []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if unmarshalErr := json.Unmarshal([]byte(output), &payload); unmarshalErr != nil {
		t.Fatalf("Unmarshal returned error: %v\noutput=%s", unmarshalErr, output)
	}
	if payload.Verified {
		t.Fatal("expected verified=false")
	}
	foundVersion := false
	foundSecretDiscoverySkip := false
	for _, check := range payload.Checks {
		switch check.Name {
		case doctor.CheckNameKeysealVersion:
			foundVersion = true
			if check.Status != "fail" {
				t.Fatalf("expected keyseal version fail, got %#v", check)
			}
		case "secret discovery":
			foundSecretDiscoverySkip = true
			if check.Status != "skip" {
				t.Fatalf("expected secret discovery skip, got %#v", check)
			}
		default:
			if strings.HasPrefix(check.Name, "secret ") && check.Status != "skip" {
				t.Fatalf("expected no per-secret decrypt checks when version fails, got %#v", check)
			}
		}
	}
	if !foundVersion {
		t.Fatalf("expected %q check in verify json, got %#v", doctor.CheckNameKeysealVersion, payload.Checks)
	}
	if !foundSecretDiscoverySkip {
		t.Fatalf("expected secret discovery skip in verify json, got %#v", payload.Checks)
	}
}

func TestValidateFailsOnKeysealVersionRequirement(t *testing.T) {
	orig := buildinfo.Version
	buildinfo.Version = "v0.2.0"
	t.Cleanup(func() { buildinfo.Version = orig })

	repoRoot := seedContractRepo(t, `  production-app:
    documents: [production/platform/app]
    required: [APP_ENV]
`)
	appendRequirementsYAML(t, repoRoot, ">=1.1.0")

	output, err := runRootCommand(t, repoRoot, "validate", "production-app", "--json")
	if err == nil {
		t.Fatal("expected validate to fail when Keyseal binary is too old")
	}
	var payload struct {
		Passed bool   `json:"passed"`
		Error  string `json:"error"`
	}
	if unmarshalErr := json.Unmarshal([]byte(output), &payload); unmarshalErr != nil {
		t.Fatalf("Unmarshal returned error: %v\n%s", unmarshalErr, output)
	}
	if payload.Passed {
		t.Fatal("expected passed=false")
	}
	if !strings.Contains(payload.Error, "v0.2.0") || !strings.Contains(payload.Error, ">=1.1.0") {
		t.Fatalf("validate error should name running and required versions, got %q", payload.Error)
	}
	for _, marker := range secretPlaintextMarkers() {
		if strings.Contains(output, marker) || strings.Contains(payload.Error, marker) {
			t.Fatalf("validate leaked decrypted secret content %q: %q", marker, output)
		}
	}
}

func TestRenderFailsOnKeysealVersionRequirement(t *testing.T) {
	orig := buildinfo.Version
	buildinfo.Version = "v0.2.0"
	t.Cleanup(func() { buildinfo.Version = orig })

	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	appendRequirementsYAML(t, repoRoot, ">=1.1.0")

	outPath := filepath.Join(repoRoot, "should-not-write.env")
	output, err := runRootCommand(t, repoRoot, "render", "production/platform/app", "--out", outPath)
	if err == nil {
		t.Fatal("expected render to fail when Keyseal binary is too old")
	}
	msg := err.Error()
	if output != "" {
		msg = output + "\n" + msg
	}
	if !strings.Contains(msg, "v0.2.0") || !strings.Contains(msg, ">=1.1.0") {
		t.Fatalf("render error should name running and required versions, got %q", msg)
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatalf("render must not write output when version requirement fails; stat=%v", statErr)
	}
}

func TestAppendVerifyContractChecksFailsWhenConfigMissing(t *testing.T) {
	dir := t.TempDir()
	result := doctor.Result{}
	result.Add(doctor.CheckResult{
		Name:     "keyseal.yaml",
		Status:   doctor.StatusOK,
		Severity: doctor.SeverityInformational,
		Summary:  "synthetic prior doctor success",
	})

	appendVerifyContractChecks(dir, &result)

	found := false
	for _, check := range result.Checks {
		if check.Name == CheckNameContractEvaluation {
			found = true
			if check.Status != doctor.StatusFail {
				t.Fatalf("expected contract evaluation fail, got %#v", check)
			}
		}
	}
	if !found {
		t.Fatalf("expected %q check, got %#v", CheckNameContractEvaluation, result.Checks)
	}
	if result.VerifyPassed() {
		t.Fatal("expected verify to fail when config reload fails after doctor")
	}
}

func appendRequirementsYAML(t *testing.T, root, constraint string) {
	t.Helper()
	path := filepath.Join(root, "keyseal.yaml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	body = append(body, []byte("\nrequirements:\n  keyseal: \""+constraint+"\"\n")...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// seedVerifyRepo creates a Keyseal repo with real .sops.yaml recipients for
// verify tests.
func seedVerifyRepo(t *testing.T) string {
	t.Helper()
	repoRoot := seedKeysealRepo(t, false)
	writeValidSOPSConfig(t, repoRoot)
	return repoRoot
}

// configureFakeAge installs a version-capable age stub so clean verify tests do
// not inherit host tool availability.
func configureFakeAge(t *testing.T, root string) {
	t.Helper()
	writeFakeSOPS(t, filepath.Join(root, "bin", "age"), "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf 'age 1.2.0\\n'\n  exit 0\nfi\nexit 0\n")
}
