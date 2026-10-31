package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testUnrelatedCredentialKey = "KEYSEAL_TEST_UNRELATED"
const testUnrelatedCredentialValue = "keyseal-test-unrelated"
const testPathMarker = "/keyseal-test-path-marker"

func TestExecDefaultInheritsUnrelatedParentCredential(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	configureVersionOnlySOPS(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	t.Setenv(testUnrelatedCredentialKey, testUnrelatedCredentialValue)
	t.Setenv("PATH", testPathMarker+":"+os.Getenv("PATH"))

	probePath := filepath.Join(repoRoot, "probe.txt")
	_, err := runRootCommand(t, repoRoot, "exec", "production/platform/app", "--", "/bin/sh", "-c", execProbeScript, "sh", probePath)
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	probe := readProbe(t, probePath)
	if probe["CREDENTIAL"] != "present" {
		t.Fatalf("expected default inheritance to pass planted credential, probe=%v", probe)
	}
	if probe["APP_ENV"] != "production" {
		t.Fatalf("expected secret APP_ENV, probe=%v", probe)
	}
	if probe["PATH_MARKER"] != "present" {
		t.Fatalf("expected default inheritance to keep parent PATH marker, probe=%v", probe)
	}
}

func TestExecCleanEnvDropsUnrelatedParentCredential(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	configureVersionOnlySOPS(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	t.Setenv(testUnrelatedCredentialKey, testUnrelatedCredentialValue)
	// Shells may invent a default PATH when unset; a unique parent marker proves
	// the parent PATH was not copied into the child.
	t.Setenv("PATH", testPathMarker+":/bin:/usr/bin")

	probePath := filepath.Join(repoRoot, "probe.txt")
	_, err := runRootCommand(
		t,
		repoRoot,
		"exec",
		"production/platform/app",
		"--clean-env",
		"--",
		"/bin/sh",
		"-c",
		execProbeScript,
		"sh",
		probePath,
	)
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	probe := readProbe(t, probePath)
	if probe["CREDENTIAL"] != "absent" {
		t.Fatalf("expected --clean-env to drop planted credential, probe=%v", probe)
	}
	if probe["APP_ENV"] != "production" {
		t.Fatalf("expected secret APP_ENV under --clean-env, probe=%v", probe)
	}
	if probe["PATH_MARKER"] != "absent" {
		t.Fatalf("expected parent PATH marker absent without --keep-env, probe=%v", probe)
	}
}

func TestExecCleanEnvKeepEnvRetainsAllowlist(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	configureVersionOnlySOPS(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	t.Setenv(testUnrelatedCredentialKey, testUnrelatedCredentialValue)
	t.Setenv("PATH", testPathMarker+":/bin:/usr/bin")

	probePath := filepath.Join(repoRoot, "probe.txt")
	_, err := runRootCommand(
		t,
		repoRoot,
		"exec",
		"production/platform/app",
		"--clean-env",
		"--keep-env",
		"PATH",
		"--",
		"/bin/sh",
		"-c",
		execProbeScript,
		"sh",
		probePath,
	)
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	probe := readProbe(t, probePath)
	if probe["PATH_MARKER"] != "present" {
		t.Fatalf("expected kept PATH to retain parent marker, probe=%v", probe)
	}
	if probe["CREDENTIAL"] != "absent" {
		t.Fatalf("expected unrelated credential to stay absent, probe=%v", probe)
	}
	if probe["APP_ENV"] != "production" {
		t.Fatalf("expected secret APP_ENV, probe=%v", probe)
	}
}

func TestExecCleanEnvSecretsOverrideKeptParentValues(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	configureVersionOnlySOPS(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	t.Setenv("APP_ENV", "from-parent")

	probePath := filepath.Join(repoRoot, "probe.txt")
	_, err := runRootCommand(
		t,
		repoRoot,
		"exec",
		"production/platform/app",
		"--clean-env",
		"--keep-env",
		"APP_ENV",
		"--",
		"/bin/sh",
		"-c",
		execProbeScript,
		"sh",
		probePath,
	)
	if err != nil {
		t.Fatalf("runRootCommand returned error: %v", err)
	}
	probe := readProbe(t, probePath)
	if probe["APP_ENV"] != "production" {
		t.Fatalf("expected secret to override kept parent APP_ENV, probe=%v", probe)
	}
}

func TestExecKeepEnvRequiresCleanEnv(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	configureVersionOnlySOPS(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	probePath := filepath.Join(repoRoot, "probe.txt")

	_, err := runRootCommand(
		t,
		repoRoot,
		"exec",
		"production/platform/app",
		"--keep-env",
		"PATH",
		"--",
		"/bin/sh",
		"-c",
		execProbeScript,
		"sh",
		probePath,
	)
	if err == nil {
		t.Fatal("expected --keep-env without --clean-env to fail")
	}
	if err.Error() == "" {
		t.Fatal("expected a visible validation error, got empty commandExitError")
	}
	if !strings.Contains(err.Error(), "--keep-env requires --clean-env") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(probePath); !os.IsNotExist(statErr) {
		t.Fatalf("child must not run when flags are invalid: stat err=%v", statErr)
	}
}

func TestExecMissingKeepEnvFailsBeforeChild(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestConfig(t, repoRoot)
	configureVersionOnlySOPS(t, repoRoot)
	writeEncryptedFixture(t, repoRoot, "production/platform/app.enc.yaml")
	probePath := filepath.Join(repoRoot, "probe.txt")
	missing := "KEYSEAL_MISSING_KEEP_ENV_XYZ"

	_, err := runRootCommand(
		t,
		repoRoot,
		"exec",
		"production/platform/app",
		"--clean-env",
		"--keep-env",
		missing,
		"--",
		"/bin/sh",
		"-c",
		execProbeScript,
		"sh",
		probePath,
	)
	if err == nil {
		t.Fatal("expected missing keep-env name to fail")
	}
	if err.Error() == "" {
		t.Fatal("expected a visible validation error, got empty commandExitError")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("expected missing name in error, got %v", err)
	}
	if strings.Contains(err.Error(), testUnrelatedCredentialValue) {
		t.Fatalf("error must not include credential values: %v", err)
	}
	if _, statErr := os.Stat(probePath); !os.IsNotExist(statErr) {
		t.Fatalf("child must not run when keep-env is missing: stat err=%v", statErr)
	}
}

// execProbeScript writes only presence/absence markers and the known APP_ENV
// fixture value. It never dumps the full child environment.
const execProbeScript = `{
  if [ -n "${` + testUnrelatedCredentialKey + `+x}" ]; then
    printf 'CREDENTIAL=present\n'
  else
    printf 'CREDENTIAL=absent\n'
  fi
  printf 'APP_ENV=%s\n' "$APP_ENV"
  case ":$PATH:" in
    *:` + testPathMarker + `:*) printf 'PATH_MARKER=present\n' ;;
    *) printf 'PATH_MARKER=absent\n' ;;
  esac
} > "$1"`

func readProbe(t *testing.T, path string) map[string]string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	probe := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("unexpected probe line %q in %q", line, body)
		}
		probe[key] = value
	}
	return probe
}
