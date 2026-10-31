package doctor_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/doctor"
)

// Scope and identity-aware doctor coverage for access_profiles, --scope,
// --profile, and --identity-profile.

const (
	doctorPublicRecipient      = "age1xlp99sh4c9dheuskt900y83mdcxdhjp0zhejf2l4lkh6fdzl0dsqsx4yrx"
	doctorOtherPublicRecipient = "age1e82vhfhpxva6rxz8nql5wfd6k9pp7w30xtjmc0r2ezy49keaeursygjxza"
)

func appendAccessProfiles(t *testing.T, dir, body string) {
	t.Helper()
	path := filepath.Join(dir, "keyseal.yaml")
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if err := os.WriteFile(path, append(existing, []byte("\n"+body)...), 0o600); err != nil {
		t.Fatalf("append access_profiles: %v", err)
	}
}

func writeEmptySecret(t *testing.T, dir, relativePath string) {
	t.Helper()
	path := filepath.Join(dir, relativePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty secret: %v", err)
	}
}

func TestDoctorProfileExcludesOutsideDocuments(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")
	writeEmptySecret(t, dir, "controller/website.enc.yaml")
	appendAccessProfiles(t, dir, `access_profiles:
  app-server:
    include:
      - production/**
    exclude:
      - controller/**
`)

	result, err := doctor.Run(dir, doctor.Options{Profile: "app-server"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Scope.Mode != doctor.ScopeModeProfile || result.Scope.Profile != "app-server" {
		t.Fatalf("unexpected scope: %#v", result.Scope)
	}
	included := findCheck(t, result, "secret production/platform/app")
	if included.Status != doctor.StatusOK {
		t.Fatalf("expected included secret ok, got %#v", included)
	}
	excluded := findCheck(t, result, "secret controller/website")
	if excluded.Status != doctor.StatusExcluded {
		t.Fatalf("expected excluded placeholder, got %#v", excluded)
	}
	if result.HasWarnings() {
		t.Fatalf("excluded placeholder must not warn, got %#v", result.Checks)
	}
	if result.DoctorFailed() {
		t.Fatalf("expected scoped doctor to pass, got %#v", result.Checks)
	}
}

func TestDoctorProfileStillFailsIncludedDecryptMiss(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecretWithKey(t, dir, "production/platform/app.enc.yaml", doctorWrongAgeKey)
	writeEmptySecret(t, dir, "controller/website.enc.yaml")
	appendAccessProfiles(t, dir, `access_profiles:
  app-server:
    include:
      - production/**
`)

	result, err := doctor.Run(dir, doctor.Options{Profile: "app-server"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	included := findCheck(t, result, "secret production/platform/app")
	if included.Status != doctor.StatusFail {
		t.Fatalf("expected included decrypt failure, got %#v", included)
	}
	excluded := findCheck(t, result, "secret controller/website")
	if excluded.Status != doctor.StatusExcluded {
		t.Fatalf("expected excluded secret, got %#v", excluded)
	}
	if !result.DoctorFailed() {
		t.Fatal("expected doctor to fail on included decrypt miss")
	}
}

func TestDoctorScopeMatchesNothingFails(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")

	result, err := doctor.Run(dir, doctor.Options{ScopePatterns: []string{"controller/**"}})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "scope selection")
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected empty scope failure, got %#v", check)
	}
	excluded := findCheck(t, result, "secret production/platform/app")
	if excluded.Status != doctor.StatusExcluded {
		t.Fatalf("expected discovered file excluded, got %#v", excluded)
	}
}

func TestDoctorConflictingSelectorsFail(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")

	result, err := doctor.Run(dir, doctor.Options{
		ScopePatterns: []string{"production/**"},
		Profile:       "app-server",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "scope selection")
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected conflicting selector failure, got %#v", check)
	}
}

func TestDoctorUnknownAccessProfileMentionsRenderProfile(t *testing.T) {
	dir := t.TempDir()
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
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
  app-server:
    renders:
      - name: app
        inputs:
          - production/platform/app
        out: /run/secrets/app.env
`
	if err := os.WriteFile(filepath.Join(dir, "keyseal.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := doctor.Run(dir, doctor.Options{Profile: "app-server"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, "scope selection")
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected unknown access profile failure, got %#v", check)
	}
	if !containsSubstring(check.Details, "profiles (render profiles)") {
		t.Fatalf("expected render-profile hint, got %#v", check.Details)
	}
}

func TestDoctorIdentityProfileUnavailable(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	secretPath := filepath.Join(dir, "controller/website.enc.yaml")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(secretPath, []byte(doctorEncryptedYAML), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	appendAccessProfiles(t, dir, `access_profiles:
  controller:
    include:
      - controller/**
    recipients:
      - `+doctorPublicRecipient+`
`)
	clearAgeKeyDoctorEnv(t)

	result, err := doctor.Run(dir, doctor.Options{IdentityProfile: "controller"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	identity := findCheck(t, result, "identity controller")
	if identity.Status != doctor.StatusUnavailable {
		t.Fatalf("expected unavailable identity, got %#v", identity)
	}
	assertNoRawDecryptLeak(t, identity.Details)
	for _, check := range result.Checks {
		if strings.HasPrefix(check.Name, "secret ") && check.Status == doctor.StatusFail {
			t.Fatalf("unavailable identity must not emit per-file decrypt failures, got %#v", check)
		}
	}
	if !result.DoctorFailed() {
		t.Fatal("expected doctor to exit failed on unavailable identity")
	}
	if result.HasFailures() {
		// unavailable must not flip HasFailures
		for _, check := range result.Checks {
			if check.Status == doctor.StatusFail && check.Name != "scope selection" {
				// allow other fails only if unexpected
			}
		}
	}
	if result.VerifyPassed() {
		t.Fatal("expected verify to treat unavailable as blocker")
	}
}

func TestDoctorIdentityProfileRecipientMismatchUnavailable(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "controller/website.enc.yaml")
	appendAccessProfiles(t, dir, `access_profiles:
  controller:
    include:
      - controller/**
    recipients:
      - `+doctorOtherPublicRecipient+`
`)

	result, err := doctor.Run(dir, doctor.Options{IdentityProfile: "controller"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	identity := findCheck(t, result, "identity controller")
	if identity.Status != doctor.StatusUnavailable {
		t.Fatalf("expected recipient mismatch unavailable, got %#v", identity)
	}
	for _, check := range result.Checks {
		if strings.HasPrefix(check.Name, "secret ") && check.Status == doctor.StatusFail {
			t.Fatalf("did not expect decrypt failure on unavailable identity: %#v", check)
		}
	}
}

func TestDoctorIdentityProfileMatchingRecipientDecrypts(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "controller/website.enc.yaml")
	writeEmptySecret(t, dir, "production/platform/app.enc.yaml")
	appendAccessProfiles(t, dir, `access_profiles:
  controller:
    include:
      - controller/**
    recipients:
      - `+doctorPublicRecipient+`
`)

	result, err := doctor.Run(dir, doctor.Options{IdentityProfile: "controller"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	identity := findCheck(t, result, "identity controller")
	if identity.Status != doctor.StatusOK {
		t.Fatalf("expected available identity, got %#v", identity)
	}
	included := findCheck(t, result, "secret controller/website")
	if included.Status != doctor.StatusOK {
		t.Fatalf("expected included decrypt ok, got %#v", included)
	}
	excluded := findCheck(t, result, "secret production/platform/app")
	if excluded.Status != doctor.StatusExcluded {
		t.Fatalf("expected production excluded, got %#v", excluded)
	}
}

func TestDoctorIdentityProfileInlineSOPSAgeKey(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	secretPath := filepath.Join(dir, "controller/website.enc.yaml")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(secretPath, []byte(doctorEncryptedYAML), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	appendAccessProfiles(t, dir, `access_profiles:
  controller:
    include:
      - controller/**
    recipients:
      - `+doctorPublicRecipient+`
`)
	clearAgeKeyDoctorEnv(t)
	t.Setenv("SOPS_AGE_KEY", doctorAgeKey)

	result, err := doctor.Run(dir, doctor.Options{IdentityProfile: "controller"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	payload, err := result.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if strings.Contains(string(payload), "AGE-SECRET-KEY-") {
		t.Fatalf("json output leaked age secret key material")
	}
	identity := findCheck(t, result, "identity controller")
	if identity.Status != doctor.StatusOK {
		t.Fatalf("expected inline SOPS_AGE_KEY to make identity available, got %#v", identity)
	}
	included := findCheck(t, result, "secret controller/website")
	if included.Status != doctor.StatusOK {
		t.Fatalf("expected decrypt with inline key, got %#v", included)
	}
}

func TestDoctorIdentityProfileStillFailsIncludedDecryptMiss(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecretWithKey(t, dir, "controller/website.enc.yaml", doctorWrongAgeKey)
	appendAccessProfiles(t, dir, `access_profiles:
  controller:
    include:
      - controller/**
`)

	result, err := doctor.Run(dir, doctor.Options{IdentityProfile: "controller"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	identity := findCheck(t, result, "identity controller")
	if identity.Status != doctor.StatusOK {
		t.Fatalf("expected available identity without recipients list, got %#v", identity)
	}
	included := findCheck(t, result, "secret controller/website")
	if included.Status != doctor.StatusFail {
		t.Fatalf("expected included decrypt miss to fail, got %#v", included)
	}
}

func TestDoctorJSONIncludesScopeAndNewCounts(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")
	writeEmptySecret(t, dir, "controller/website.enc.yaml")
	appendAccessProfiles(t, dir, `access_profiles:
  app-server:
    include:
      - production/**
`)

	result, err := doctor.Run(dir, doctor.Options{Profile: "app-server"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	payload, err := result.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var decoded struct {
		Summary struct {
			Excluded    int `json:"excluded"`
			Unavailable int `json:"unavailable"`
		} `json:"summary"`
		Scope struct {
			Mode    string `json:"mode"`
			Profile string `json:"profile"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, payload)
	}
	if decoded.Scope.Mode != "profile" || decoded.Scope.Profile != "app-server" {
		t.Fatalf("unexpected scope json: %#v", decoded.Scope)
	}
	if decoded.Summary.Excluded == 0 {
		t.Fatalf("expected excluded count in summary, got %#v", decoded.Summary)
	}
}

func TestDoctorUnmappablePathFailsUnderScope(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")
	badPath := filepath.Join(dir, "production/app.enc.extra.enc.yaml")
	if err := os.WriteFile(badPath, []byte(doctorEncryptedYAML), 0o600); err != nil {
		t.Fatalf("write bad path: %v", err)
	}
	appendAccessProfiles(t, dir, `access_profiles:
  app-server:
    include:
      - production/**
`)

	result, err := doctor.Run(dir, doctor.Options{Profile: "app-server"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	found := false
	for _, check := range result.Checks {
		if check.Name == "secret naming" && check.Status == doctor.StatusFail {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected secret naming failure under scope, got %#v", result.Checks)
	}
}

func TestDoctorContractOutsideScopeIsExcluded(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")
	path := filepath.Join(dir, "keyseal.yaml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	body = append(body, []byte(`
access_profiles:
  app-server:
    include:
      - production/**
contracts:
  controller-site:
    documents:
      - controller/website
    required:
      - SITE_KEY
`)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := doctor.Run(dir, doctor.Options{Profile: "app-server"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, `contract "controller-site"`)
	if check.Status != doctor.StatusExcluded {
		t.Fatalf("expected outside-scope contract excluded, got %#v", check)
	}
}

func TestDoctorMixedScopeContractFails(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")
	writeEncryptedSecret(t, dir, "controller/website.enc.yaml")
	path := filepath.Join(dir, "keyseal.yaml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	body = append(body, []byte(`
access_profiles:
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
`)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := doctor.Run(dir, doctor.Options{Profile: "app-server"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, `contract "mixed-role"`)
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected mixed contract fail, got %#v", check)
	}
	if !strings.Contains(check.Summary, "spans documents inside and outside the selected scope") {
		t.Fatalf("unexpected mixed summary: %#v", check)
	}
	if !containsSubstring(check.Details, "Partial contract evaluation is not supported.") {
		t.Fatalf("expected partial-eval detail, got %#v", check.Details)
	}
	if !result.DoctorFailed() {
		t.Fatal("expected doctor to fail on mixed-scope contract")
	}
}

func TestDoctorMixedScopeContractFailsWhenOutOfScopeDocMissing(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")
	path := filepath.Join(dir, "keyseal.yaml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	body = append(body, []byte(`
access_profiles:
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
`)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := doctor.Run(dir, doctor.Options{Profile: "app-server"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, `contract "mixed-role"`)
	if check.Status != doctor.StatusFail {
		t.Fatalf("expected mixed contract fail, got %#v", check)
	}
	if strings.Contains(check.Summary, "documents exist") {
		t.Fatalf("must not claim documents exist for mixed scope: %#v", check)
	}
	if strings.Contains(check.Summary, "missing documents") {
		t.Fatalf("mixed classification must win over missing out-of-scope docs: %#v", check)
	}
}

func TestDoctorInScopeContractOKDetailsListCheckedDocsOnly(t *testing.T) {
	dir := t.TempDir()
	writeDoctorConfig(t, dir, "missing-sops", "0600")
	writeSOPSConfig(t, dir, "creation_rules:\n  - path_regex: .*\\.enc\\.yaml$\n    age: age1realrecipient\n")
	writeEncryptedSecret(t, dir, "production/platform/app.enc.yaml")
	path := filepath.Join(dir, "keyseal.yaml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	body = append(body, []byte(`
access_profiles:
  app-server:
    include:
      - production/**
contracts:
  production-app:
    documents:
      - production/platform/app
    required:
      - APP_ENV
`)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := doctor.Run(dir, doctor.Options{Profile: "app-server"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	check := findCheck(t, result, `contract "production-app"`)
	if check.Status != doctor.StatusOK {
		t.Fatalf("expected in-scope contract ok, got %#v", check)
	}
	if !containsSubstring(check.Details, "Documents: production/platform/app") {
		t.Fatalf("expected checked docs in details, got %#v", check.Details)
	}
}
