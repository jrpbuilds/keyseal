package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func appendContractsYAML(t *testing.T, root, contractsBody string) {
	t.Helper()
	path := filepath.Join(root, "keyseal.yaml")
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read keyseal.yaml: %v", err)
	}
	body := string(existing) + "\ncontracts:\n" + contractsBody
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write keyseal.yaml: %v", err)
	}
}

func seedContractRepo(t *testing.T, contractsBody string) string {
	t.Helper()
	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	appendContractsYAML(t, repoRoot, contractsBody)
	return repoRoot
}

func TestDoctorContractDefinitionOKWithoutValueEvaluation(t *testing.T) {
	repoRoot := seedContractRepo(t, `  production-app:
    documents: [production/platform/app]
    required: [MISSING_REQUIRED_KEY]
`)
	output, err := runRootCommand(t, repoRoot, "doctor")
	if err != nil {
		t.Fatalf("doctor should pass when only contract values fail: %v\n%s", err, output)
	}
	if !strings.Contains(output, `[OK] contract "production-app"`) {
		t.Fatalf("expected doctor contract definition OK, got %q", output)
	}
}

func TestDoctorContractMalformedDefinitionFails(t *testing.T) {
	repoRoot := seedContractRepo(t, `  production-app:
    documents: [production/platform/app]
    rules:
      - key: APP_ENV
        matches: "("
`)
	output, err := runRootCommand(t, repoRoot, "doctor")
	if err == nil {
		t.Fatal("expected doctor to fail on malformed contract")
	}
	if !strings.Contains(output, `[FAIL] contract "production-app"`) {
		t.Fatalf("expected contract failure, got %q", output)
	}
}

func TestVerifyFailsOnContractViolationWithoutLeakingValues(t *testing.T) {
	repoRoot := seedContractRepo(t, `  production-app:
    documents: [production/platform/app]
    required: [MISSING_REQUIRED_KEY]
`)
	output, err := runRootCommand(t, repoRoot, "verify")
	if err == nil {
		t.Fatal("expected verify to fail on contract violation")
	}
	if !strings.Contains(output, `contract "production-app"`) {
		t.Fatalf("expected contract check in verify output, got %q", output)
	}
	if !strings.Contains(output, "MISSING_REQUIRED_KEY") {
		t.Fatalf("expected missing key name, got %q", output)
	}
	for _, marker := range secretPlaintextMarkers() {
		if strings.Contains(output, marker) {
			t.Fatalf("verify output leaked secret content %q: %q", marker, output)
		}
	}
}

func secretPlaintextMarkers() []string {
	// Decrypted fixture contains APP_ENV=production and DB_HOST=db. These may
	// appear in logical paths; assert they are not printed as assigned values.
	return []string{"DB_HOST: db", "APP_ENV: production"}
}

func TestVerifyPassesWhenContractSatisfied(t *testing.T) {
	repoRoot := seedContractRepo(t, `  production-app:
    documents: [production/platform/app]
    required: [APP_ENV]
`)
	output, err := runRootCommand(t, repoRoot, "verify")
	if err != nil {
		t.Fatalf("expected verify to pass: %v\n%s", err, output)
	}
	if !strings.Contains(output, "verify passed:") {
		t.Fatalf("expected verify pass, got %q", output)
	}
}

func TestVerifyUnchangedWithoutContracts(t *testing.T) {
	repoRoot := seedVerifyRepo(t)
	configureVersionOnlySOPS(t, repoRoot)
	configureFakeAge(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")

	output, err := runRootCommand(t, repoRoot, "verify")
	if err != nil {
		t.Fatalf("expected verify to pass without contracts: %v\n%s", err, output)
	}
	if strings.Contains(output, "contract ") {
		t.Fatalf("expected no contract checks, got %q", output)
	}
}

func TestValidateJSONPassAndFail(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		repoRoot := seedContractRepo(t, `  production-app:
    documents: [production/platform/app]
    required: [APP_ENV]
`)
		output, err := runRootCommand(t, repoRoot, "validate", "production-app", "--json")
		if err != nil {
			t.Fatalf("validate --json returned error: %v\n%s", err, output)
		}
		var payload struct {
			Contract   string `json:"contract"`
			Passed     bool   `json:"passed"`
			Violations []any  `json:"violations"`
		}
		if unmarshalErr := json.Unmarshal([]byte(output), &payload); unmarshalErr != nil {
			t.Fatalf("Unmarshal returned error: %v\n%s", unmarshalErr, output)
		}
		if !payload.Passed || payload.Contract != "production-app" || payload.Violations == nil {
			t.Fatalf("unexpected payload: %#v", payload)
		}
	})

	t.Run("violation", func(t *testing.T) {
		repoRoot := seedContractRepo(t, `  production-app:
    documents: [production/platform/app]
    required: [MISSING_REQUIRED_KEY]
`)
		output, err := runRootCommand(t, repoRoot, "validate", "production-app", "--json")
		if err == nil {
			t.Fatal("expected validate to fail")
		}
		var payload struct {
			Passed     bool `json:"passed"`
			Violations []struct {
				Rule    string   `json:"rule"`
				Keys    []string `json:"keys"`
				Message string   `json:"message"`
			} `json:"violations"`
		}
		if unmarshalErr := json.Unmarshal([]byte(output), &payload); unmarshalErr != nil {
			t.Fatalf("Unmarshal returned error: %v\n%s", unmarshalErr, output)
		}
		if payload.Passed || len(payload.Violations) == 0 {
			t.Fatalf("unexpected payload: %#v", payload)
		}
		if payload.Violations[0].Rule != "required" {
			t.Fatalf("expected required violation, got %#v", payload.Violations[0])
		}
		for _, marker := range secretPlaintextMarkers() {
			if strings.Contains(output, marker) {
				t.Fatalf("validate JSON leaked secret content %q: %s", marker, output)
			}
		}
	})

	t.Run("unknown contract", func(t *testing.T) {
		repoRoot := seedContractRepo(t, `  production-app:
    documents: [production/platform/app]
`)
		output, err := runRootCommand(t, repoRoot, "validate", "missing-contract", "--json")
		if err == nil {
			t.Fatal("expected unknown contract to fail")
		}
		var payload struct {
			Passed bool   `json:"passed"`
			Error  string `json:"error"`
		}
		if unmarshalErr := json.Unmarshal([]byte(output), &payload); unmarshalErr != nil {
			t.Fatalf("Unmarshal returned error: %v\n%s", unmarshalErr, output)
		}
		if payload.Passed || !strings.Contains(payload.Error, "not defined") {
			t.Fatalf("unexpected payload: %#v", payload)
		}
	})

	t.Run("decrypt failure", func(t *testing.T) {
		repoRoot := seedVerifyRepo(t)
		configureVersionOnlySOPS(t, repoRoot)
		configureFakeAge(t, repoRoot)
		writeCLIFile(t, filepath.Join(repoRoot, "production/platform/app.enc.yaml"), "not-encrypted\n")
		appendContractsYAML(t, repoRoot, `  production-app:
    documents: [production/platform/app]
    required: [APP_ENV]
`)
		output, err := runRootCommand(t, repoRoot, "validate", "production-app", "--json")
		if err == nil {
			t.Fatal("expected decrypt/load failure")
		}
		var payload struct {
			Passed     bool `json:"passed"`
			Violations []struct {
				Rule string `json:"rule"`
			} `json:"violations"`
		}
		if unmarshalErr := json.Unmarshal([]byte(output), &payload); unmarshalErr != nil {
			t.Fatalf("Unmarshal returned error: %v\n%s", unmarshalErr, output)
		}
		if payload.Passed || len(payload.Violations) == 0 || payload.Violations[0].Rule != "load" {
			t.Fatalf("expected load violation, got %#v from %s", payload, output)
		}
	})
}

func TestInitConfigYAMLOmitsContracts(t *testing.T) {
	body := defaultConfigYAML("default")
	if strings.Contains(body, "contracts:") {
		t.Fatalf("init YAML must omit contracts key, got %s", body)
	}
}
