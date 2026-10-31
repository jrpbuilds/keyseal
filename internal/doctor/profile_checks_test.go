package doctor_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/doctor"
)

// writeDoctorProfilesConfig writes a keyseal.yaml whose profiles section is
// the given YAML fragment, keeping every other section doctor-valid.
func writeDoctorProfilesConfig(t *testing.T, dir, profiles string) {
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
` + profiles
	if err := os.WriteFile(filepath.Join(dir, "keyseal.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// TestDoctorProfileChecks asserts the aggregated per-render and per-profile
// check names, statuses, and details for each violation class.
func TestDoctorProfileChecks(t *testing.T) {
	t.Run("malformed render reports format and mode failures", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorProfilesConfig(t, dir, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        format: xml
        out: /run/secrets/app.env
        mode: "999"
`)

		result, err := doctor.Run(dir, doctor.Options{})
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `profile "prod" render "app"`)
		if check.Status != doctor.StatusFail {
			t.Fatalf("expected per-render FAIL, got %#v", check)
		}
		if !containsSubstring(check.Details, `format "xml"`) || !containsSubstring(check.Details, `mode "999"`) {
			t.Fatalf("expected format and mode details, got %#v", check.Details)
		}
		// Existing non-profile checks are still present.
		configCheck := findCheck(t, result, "keyseal.yaml")
		if configCheck.Status != doctor.StatusOK {
			t.Fatalf("expected keyseal.yaml check to stay OK under lenient load, got %#v", configCheck)
		}
	})

	t.Run("duplicate out paths reported per profile", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorProfilesConfig(t, dir, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        out: /run/secrets/a//app.env
      - name: stripe
        inputs:
          - production/platform/stripe
        out: /run/secrets/./a/app.env
`)

		result, err := doctor.Run(dir, doctor.Options{})
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `profile "prod" duplicate output`)
		if check.Status != doctor.StatusFail {
			t.Fatalf("expected duplicate-output FAIL, got %#v", check)
		}
		if !containsSubstring(check.Details, `renders "app" and "stripe"`) {
			t.Fatalf("expected both render names in details, got %#v", check.Details)
		}
	})

	t.Run("missing profile input reported without decrypting", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorProfilesConfig(t, dir, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/absent
        out: /run/secrets/app.env
`)

		result, err := doctor.Run(dir, doctor.Options{})
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `profile "prod" render "app"`)
		if check.Status != doctor.StatusFail {
			t.Fatalf("expected missing-input FAIL, got %#v", check)
		}
		if !containsSubstring(check.Details, `input "production/platform/absent" is missing at`) {
			t.Fatalf("expected missing-input detail, got %#v", check.Details)
		}
	})

	t.Run("invalid logical-name shape and empty inputs reported", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorProfilesConfig(t, dir, `  prod:
    renders:
      - name: broken
        inputs:
          - ../escape
        out: /run/secrets/broken.env
`)

		result, err := doctor.Run(dir, doctor.Options{})
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `profile "prod" render "broken"`)
		if check.Status != doctor.StatusFail {
			t.Fatalf("expected logical-name FAIL, got %#v", check)
		}
		if !containsSubstring(check.Details, `not a valid logical name`) {
			t.Fatalf("expected logical-name detail, got %#v", check.Details)
		}
	})

	t.Run("empty inputs reported", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorProfilesConfig(t, dir, `  prod:
    renders:
      - name: noinputs
        inputs: []
        out: /run/secrets/noinputs.env
`)

		result, err := doctor.Run(dir, doctor.Options{})
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `profile "prod" render "noinputs"`)
		if check.Status != doctor.StatusFail {
			t.Fatalf("expected empty-inputs FAIL, got %#v", check)
		}
		if !containsSubstring(check.Details, "inputs is empty") {
			t.Fatalf("expected empty-inputs detail, got %#v", check.Details)
		}
	})

	t.Run("empty out reported", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorProfilesConfig(t, dir, `  prod:
    renders:
      - name: noout
        inputs:
          - production/platform/app
        out: ""
`)

		result, err := doctor.Run(dir, doctor.Options{})
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		check := findCheck(t, result, `profile "prod" render "noout"`)
		if check.Status != doctor.StatusFail {
			t.Fatalf("expected empty-out FAIL, got %#v", check)
		}
		if !containsSubstring(check.Details, "out is required") {
			t.Fatalf("expected empty-out detail, got %#v", check.Details)
		}
	})

	t.Run("clean profile emits no profile-related failures or warnings", func(t *testing.T) {
		dir := t.TempDir()
		writeDoctorProfilesConfig(t, dir, `  prod:
    renders:
      - name: app
        inputs:
          - production/platform/app
        format: json
        out: `+filepath.ToSlash(filepath.Join(dir, "out", "app.env"))+`
        mode: "0600"
`)
		writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: production/.*\\.enc\\.yaml$\n    age: age1realrecipient\n")
		writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")

		result, err := doctor.Run(dir, doctor.Options{})
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		renderCheck := findCheck(t, result, `profile "prod" render "app"`)
		if renderCheck.Status != doctor.StatusOK {
			t.Fatalf("expected clean per-render OK, got %#v", renderCheck)
		}
		duplicateCheck := findCheck(t, result, `profile "prod" duplicate output`)
		if duplicateCheck.Status != doctor.StatusOK {
			t.Fatalf("expected clean duplicate-output OK, got %#v", duplicateCheck)
		}
		for _, check := range result.Checks {
			if strings.HasPrefix(check.Name, "profile ") && check.Status != doctor.StatusOK {
				t.Fatalf("unexpected profile-related finding: %#v", check)
			}
		}
		if result.HasFailures() {
			t.Fatalf("expected clean repo to have no failures, got %#v", result.Checks)
		}
	})
}
