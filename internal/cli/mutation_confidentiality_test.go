package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const confidentialityMarker = "kslmarker-7f3a9c2e1b"

// installObservingSOPS wraps the real sops binary with a script that records
// its arguments and, while SOPS is running, searches the temp directory and
// the repository for the plaintext marker. When failEncrypt is set the
// wrapper fails the encrypt step after observing.
func installObservingSOPS(t *testing.T, root, tmpDir string, failEncrypt bool) string {
	t.Helper()
	realSOPS := realSOPSPath(t)
	logDir := t.TempDir()
	binDir := t.TempDir()
	encryptStep := "exec \"" + realSOPS + "\" \"$@\""
	if failEncrypt {
		encryptStep = "if [ \"$1\" = \"encrypt\" ]; then cat >/dev/null; echo 'forced failure' >&2; exit 1; fi\n" + encryptStep
	}
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> \"" + filepath.Join(logDir, "argv") + "\"\n" +
		"grep -rl \"" + confidentialityMarker + "\" \"" + tmpDir + "\" \"" + root + "\" >> \"" + filepath.Join(logDir, "hits") + "\" 2>/dev/null\n" +
		encryptStep + "\n"
	writeFakeSOPS(t, filepath.Join(binDir, "sops"), script)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logDir
}

// assertMarkerAbsent fails if the marker appears in any file under dirs.
func assertMarkerAbsent(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), confidentialityMarker) {
				t.Errorf("plaintext marker found in %s", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
}

func assertObservedClean(t *testing.T, logDir string) {
	t.Helper()
	argv := string(readBytes(t, filepath.Join(logDir, "argv")))
	if !strings.Contains(argv, "encrypt --filename-override") {
		t.Fatalf("expected the wrapper to observe a SOPS encrypt call, got %q", argv)
	}
	if strings.Contains(argv, confidentialityMarker) {
		t.Fatal("plaintext marker found in SOPS process arguments")
	}
	if hits, err := os.ReadFile(filepath.Join(logDir, "hits")); err == nil && len(strings.TrimSpace(string(hits))) > 0 {
		t.Fatalf("plaintext marker found on disk while SOPS was running: %s", hits)
	}
}

func TestMutationPlaintextNeverReachesDiskArgsOrOutput(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	logDir := installObservingSOPS(t, root, tmpDir, false)
	envFile := filepath.Join(t.TempDir(), "intake.env")
	writeFileForCLI(t, envFile, "STRIPE_CONNECT_CLIENT_ID="+confidentialityMarker+"-import\n")

	var output strings.Builder
	for _, step := range []struct {
		stdin string
		args  []string
	}{
		{confidentialityMarker + "\n", []string{"set", "production/app", "STRIPE_SECRET_KEY", "--stdin"}},
		{"", []string{"import", "production/app", "--from-env-file", envFile, "--keys", "STRIPE_CONNECT_CLIENT_ID"}},
		{"", []string{"clone", "production/app", "production/app-next"}},
		{"", []string{"unset", "production/app-next", "STRIPE_WEBHOOK_SECRET"}},
	} {
		stdout, stderr, err := runRootCommandIO(t, root, strings.NewReader(step.stdin), step.args...)
		if err != nil {
			t.Fatalf("%v returned error: %v", step.args, err)
		}
		output.WriteString(stdout + stderr)
	}

	if strings.Contains(output.String(), confidentialityMarker) {
		t.Fatal("plaintext marker found in command output")
	}
	assertObservedClean(t, logDir)
	assertMarkerAbsent(t, tmpDir, root)
	if got := decryptDoc(t, root, "production/app-next").Values["STRIPE_SECRET_KEY"]; got != confidentialityMarker {
		t.Fatal("expected the value to survive the clone")
	}
}

func TestFailedMutationPlaintextNeverReachesDiskArgsOrOutput(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	path := docPath(root, "production/app")
	before := readBytes(t, path)
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	logDir := installObservingSOPS(t, root, tmpDir, true)

	stdout, stderr, err := runRootCommandIO(t, root, strings.NewReader(confidentialityMarker), "set", "production/app", "STRIPE_SECRET_KEY", "--stdin")
	if err == nil {
		t.Fatal("expected forced SOPS failure")
	}
	if strings.Contains(err.Error()+stdout+stderr, confidentialityMarker) {
		t.Fatal("plaintext marker found in error or output")
	}
	assertUnchanged(t, path, before)
	assertObservedClean(t, logDir)
	assertMarkerAbsent(t, tmpDir, root)
}
