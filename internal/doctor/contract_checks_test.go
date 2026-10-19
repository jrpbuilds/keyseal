package doctor_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/doctor"
)

func writeDoctorContractsConfig(t *testing.T, dir, contracts string) {
	t.Helper()
	cfg := `version: 1
repository:
  root: .
  encrypted_extension: .enc.yaml
sops:
  binary: missing-sops
  age_binary: age
defaults:
  output_format: dotenv
  output_dir: /run/secrets
  file_mode: "0600"
validation:
  require_values: true
  key_pattern: "^[A-Z0-9_]+$"
profiles:
  default:
    renders: []
contracts:
` + contracts
	if err := os.WriteFile(filepath.Join(dir, "keyseal.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func TestDoctorContractDefinitionChecks(t *testing.T) {
	t.Run("well-formed contract with existing document is ok", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorContractsConfig(t, dir, `  production-app:
    documents: [production/platform/app]
    required: [APP_ENV]
`)
		writeValidSOPSConfigForDoctor(t, dir)
		writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")

		result, err := doctor.Run(dir)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `contract "production-app"`)
		if check.Status != doctor.StatusOK {
			t.Fatalf("expected OK contract check, got %#v", check)
		}
	})

	t.Run("malformed definition fails without decrypting", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorContractsConfig(t, dir, `  production-app:
    documents: [production/platform/app]
    rules:
      - key: APP_ENV
        matches: "("
`)
		writeValidSOPSConfigForDoctor(t, dir)
		writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")

		result, err := doctor.Run(dir)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `contract "production-app"`)
		if check.Status != doctor.StatusFail {
			t.Fatalf("expected FAIL contract check, got %#v", check)
		}
		if !strings.Contains(strings.Join(check.Details, "\n"), "invalid regex") {
			t.Fatalf("expected invalid regex detail, got %#v", check)
		}
	})

	t.Run("missing document fails", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorContractsConfig(t, dir, `  production-app:
    documents: [production/platform/missing]
`)
		writeValidSOPSConfigForDoctor(t, dir)

		result, err := doctor.Run(dir)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `contract "production-app"`)
		if check.Status != doctor.StatusFail {
			t.Fatalf("expected FAIL for missing document, got %#v", check)
		}
		if !strings.Contains(strings.Join(check.Details, "\n"), "missing") {
			t.Fatalf("expected missing document detail, got %#v", check)
		}
	})

	t.Run("bad from path fails", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorContractsConfig(t, dir, `  production-app:
    from: contracts/does-not-exist.yaml
`)
		writeValidSOPSConfigForDoctor(t, dir)

		result, err := doctor.Run(dir)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `contract "production-app"`)
		if check.Status != doctor.StatusFail {
			t.Fatalf("expected FAIL for bad from path, got %#v", check)
		}
	})

	t.Run("plaintext document does not leak contents into the contract check", func(t *testing.T) {
		dir := t.TempDir()
		const marker = "PLAINTEXT_SECRET_MARKER_should_not_appear"
		writeDoctorContractsConfig(t, dir, `  production-app:
    documents: [production/platform/app]
`)
		writeValidSOPSConfigForDoctor(t, dir)
		secretPath := filepath.Join(dir, "production", "platform", "app.enc.yaml")
		if err := os.MkdirAll(filepath.Dir(secretPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(secretPath, []byte("version: 1\nkind: env\nvalues:\n  TOKEN: "+marker+"\n"), 0o600); err != nil {
			t.Fatalf("write plaintext: %v", err)
		}
		result, err := doctor.Run(dir)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `contract "production-app"`)
		if check.Status != doctor.StatusOK {
			t.Fatalf("existing plaintext file still satisfies the existence check, got %#v", check)
		}
		rendered := result.RenderText()
		if strings.Contains(rendered, marker) {
			t.Fatalf("doctor output leaked plaintext secret: %s", rendered)
		}
	})

	t.Run("missing required value does not fail doctor", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorContractsConfig(t, dir, `  production-app:
    documents: [production/platform/app]
    required: [MISSING_REQUIRED_KEY]
`)
		writeValidSOPSConfigForDoctor(t, dir)
		keyPath := writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")
		_ = keyPath

		result, err := doctor.Run(dir)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `contract "production-app"`)
		if check.Status != doctor.StatusOK {
			t.Fatalf("doctor must not evaluate contract values, got %#v", check)
		}
	})
}

func writeValidSOPSConfigForDoctor(t *testing.T, dir string) {
	t.Helper()
	writeSOPSConfig(t, dir, `creation_rules:
  - path_regex: .*\.enc\.yaml$
    age: age1xlp99sh4c9dheuskt900y83mdcxdhjp0zhejf2l4lkh6fdzl0dsqsx4yrx
`)
}
