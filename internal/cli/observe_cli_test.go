package cli

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// putEncryptedDoc writes an env document encrypted for the test age identity
// with the real sops binary. values is the YAML body under `values:`.
func putEncryptedDoc(t *testing.T, root, logical, values string) {
	t.Helper()
	realSOPSPath(t)
	plaintext := "version: 1\nkind: env\nname: " + logical + "\nvalues:\n" + values
	cmd := exec.Command("sops", "encrypt", "--filename-override", logical+".enc.yaml",
		"--input-type", "yaml", "--output-type", "yaml", "--age", cliTestAgePublicKey, "--encrypted-regex", "^(name|values)$")
	cmd.Stdin = strings.NewReader(plaintext)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("sops encrypt failed: %v", err)
	}
	writeFileForCLI(t, docPath(root, logical), string(out))
}

func commitAll(t *testing.T, root string) {
	t.Helper()
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-m", "snapshot")
}

func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	var coded interface{ ExitCode() int }
	if !errors.As(err, &coded) {
		t.Fatalf("expected an error with an exit code, got %v", err)
	}
	return coded.ExitCode()
}

func decodeJSON(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, body)
	}
	return out
}

func jsonKeyField(t *testing.T, body map[string]any, field string) map[string]string {
	t.Helper()
	out := map[string]string{}
	rows, _ := body["keys"].([]any)
	for _, row := range rows {
		m := row.(map[string]any)
		out[m["name"].(string)], _ = m[field].(string)
	}
	return out
}

func TestInspectReportsStatesAndMetadataWithoutValues(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	putEncryptedDoc(t, root, "production/mixed", "  TOKEN: "+confidentialityMarker+"\n  BLANK: \"\"\n  NESTED:\n    inner: x\n")

	stdout, stderr, err := runRootCommandIO(t, root, nil, "inspect", "production/mixed")
	if err != nil || stderr != "" {
		t.Fatalf("inspect failed: %v stderr=%q", err, stderr)
	}
	for _, want := range []string{"file_state=encrypted", "TOKEN state=present\n", "BLANK state=empty\n", "NESTED state=non_scalar\n", "passed=true\n"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in:\n%s", want, stdout)
		}
	}

	stdout, _, err = runRootCommandIO(t, root, nil, "inspect", "production/mixed", "--json", "--key", "TOKEN", "--key", "ABSENT", "--show-length", "--show-type", "--redacted")
	if err != nil {
		t.Fatalf("inspect --json failed: %v", err)
	}
	if !strings.HasSuffix(stdout, "}\n") || !strings.Contains(stdout, "\n  \"keys\"") {
		t.Fatalf("expected two-space indented JSON with one trailing newline:\n%s", stdout)
	}
	body := decodeJSON(t, stdout)
	if got := jsonKeyField(t, body, "state"); !reflect.DeepEqual(got, map[string]string{"TOKEN": "present", "ABSENT": "missing"}) {
		t.Fatalf("unexpected states: %v", got)
	}
	token := body["keys"].([]any)[1].(map[string]any)
	if token["length"] != float64(len(confidentialityMarker)) || token["type"] != "str" {
		t.Fatalf("unexpected metadata: %v", token)
	}
}

func TestInspectRefusesToDisableRedaction(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)

	stdout, _, err := runRootCommandIO(t, root, nil, "inspect", "production/app", "--redacted=false")
	if err == nil || !strings.Contains(err.Error(), "--redacted=false is not supported") || stdout != "" {
		t.Fatalf("expected a refusal, got err=%v stdout=%q", err, stdout)
	}
}

func TestInspectFailsClosedWithReportAndExitCodeOne(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	writeFileForCLI(t, docPath(root, "production/placeholder"), "\n")
	writeFileForCLI(t, docPath(root, "production/plain"), "version: 1\nkind: env\nvalues:\n  TOKEN: "+confidentialityMarker+"\n")

	for name, state := range map[string]string{"production/placeholder": "placeholder", "production/plain": "plaintext", "production/absent": "missing"} {
		stdout, stderr, err := runRootCommandIO(t, root, nil, "inspect", name, "--json")
		if err == nil || exitCodeOf(t, err) != 1 || err.Error() != "" {
			t.Fatalf("%s: expected a silent exit 1, got %v", name, err)
		}
		body := decodeJSON(t, stdout)
		if body["passed"] != false || body["file_state"] != state || body["keys"] != nil {
			t.Fatalf("%s: unexpected report %v", name, body)
		}
		if stderr != "" || strings.Contains(stdout, confidentialityMarker) {
			t.Fatalf("%s: unexpected stderr=%q or leaked content", name, stderr)
		}
	}
}

func TestInspectReadsRevisionWithTo(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	putEncryptedDoc(t, root, "production/hist", "  OLD_KEY: a\n")
	commitAll(t, root)
	putEncryptedDoc(t, root, "production/hist", "  NEW_KEY: b\n")

	stdout, _, err := runRootCommandIO(t, root, nil, "inspect", "production/hist", "--to", "HEAD")
	if err != nil {
		t.Fatalf("inspect --to failed: %v", err)
	}
	if !strings.Contains(stdout, "source=revision revision=HEAD") || !strings.Contains(stdout, "OLD_KEY state=present") || strings.Contains(stdout, "NEW_KEY") {
		t.Fatalf("expected the committed document:\n%s", stdout)
	}

	stdout, _, err = runRootCommandIO(t, root, nil, "inspect", "production/hist", "--to", "no-such-rev")
	if err == nil || exitCodeOf(t, err) != 1 || !strings.Contains(stdout, `revision "no-such-rev" was not found`) {
		t.Fatalf("expected an unknown-revision failure, err=%v\n%s", err, stdout)
	}
}

func TestInspectToNeedsAGitRepositoryButWorktreeInspectDoesNot(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	if err := os.RemoveAll(filepath.Join(root, ".git")); err != nil {
		t.Fatalf("remove .git: %v", err)
	}

	if _, _, err := runRootCommandIO(t, root, nil, "inspect", "production/app"); err != nil {
		t.Fatalf("worktree inspect must not need Git: %v", err)
	}
	_, _, err := runRootCommandIO(t, root, nil, "inspect", "production/app", "--to", "HEAD")
	if err == nil || !strings.Contains(err.Error(), "not inside a Git repository") {
		t.Fatalf("expected a repository error, got %v", err)
	}
}

func TestCompareReportsOutcomesAndAssertionExitCodes(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	putEncryptedDoc(t, root, "production/left", "  SAME: one\n  DIFF: two\n  GONE: x\n  BLANK: \"\"\n")
	putEncryptedDoc(t, root, "production/right", "  SAME: one\n  DIFF: changed\n  NEW: y\n  BLANK: \"\"\n")
	putEncryptedDoc(t, root, "production/twin", "  SAME: one\n  DIFF: two\n  GONE: x\n  BLANK: \"\"\n")

	stdout, stderr, err := runRootCommandIO(t, root, nil, "compare", "production/left", "production/right", "--json")
	if err != nil || stderr != "" {
		t.Fatalf("compare failed: %v stderr=%q", err, stderr)
	}
	body := decodeJSON(t, stdout)
	want := map[string]string{"SAME": "equal", "DIFF": "different", "GONE": "removed", "NEW": "added", "BLANK": "equal"}
	if got := jsonKeyField(t, body, "outcome"); !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %v, want %v", got, want)
	}
	if body["equal"] != false || body["passed"] != true {
		t.Fatalf("unexpected summary: %v", body)
	}

	for _, tc := range []struct {
		args     []string
		wantExit int
	}{
		{[]string{"compare", "production/left", "production/twin", "--assert-equal"}, 0},
		{[]string{"compare", "production/left", "production/right", "--assert-equal"}, 1},
		{[]string{"compare", "production/left", "production/right", "--assert-unequal"}, 0},
		{[]string{"compare", "production/left", "production/twin", "--assert-unequal"}, 1},
		{[]string{"compare", "production/left", "production/right", "--key", "SAME", "--assert-equal"}, 0},
		{[]string{"compare", "production/left", "production/right", "--key", "DIFF", "--assert-equal"}, 1},
		{[]string{"compare", "production/left", "production/right", "--key", "SAME", "--key", "NOPE", "--assert-equal"}, 1},
		{[]string{"compare", "production/left", "production/missing", "--assert-equal"}, 1},
		{[]string{"compare", "production/left", "production/missing"}, 1},
	} {
		_, _, err := runRootCommandIO(t, root, nil, tc.args...)
		got := 0
		if err != nil {
			got = exitCodeOf(t, err)
		}
		if got != tc.wantExit {
			t.Errorf("%v: exit = %d, want %d (err=%v)", tc.args, got, tc.wantExit, err)
		}
	}
}

func TestCompareRejectsConflictingAssertionsAndEmptyKey(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)

	_, _, err := runRootCommandIO(t, root, nil, "compare", "production/app", "production/app", "--assert-equal", "--assert-unequal")
	if err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("expected an assertion conflict, got %v", err)
	}
	_, _, err = runRootCommandIO(t, root, nil, "compare", "production/app", "production/app", "--key", "")
	if err == nil || !strings.Contains(err.Error(), "--key requires") {
		t.Fatalf("expected an empty key refusal, got %v", err)
	}
}

func TestCompareWorksOutsideAGitRepository(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	if _, err := runRootCommand(t, root, "clone", "production/app", "production/app-next"); err != nil {
		t.Fatalf("clone failed: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(root, ".git")); err != nil {
		t.Fatalf("remove .git: %v", err)
	}

	if _, _, err := runRootCommandIO(t, root, nil, "compare", "production/app", "production/app-next", "--assert-equal"); err != nil {
		t.Fatalf("compare of two worktree documents must not need Git: %v", err)
	}
}

func TestSemanticDiffComparesWorktreeToRevision(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	putEncryptedDoc(t, root, "production/svc", "  KEEP: a\n  CHANGE: b\n  DROP: c\n")
	commitAll(t, root)
	first := strings.TrimSpace(gitOutput(t, root, "rev-parse", "HEAD"))
	putEncryptedDoc(t, root, "production/svc", "  KEEP: a\n  CHANGE: changed\n  ADD: d\n")
	commitAll(t, root)
	putEncryptedDoc(t, root, "production/svc", "  KEEP: a\n  CHANGE: changed\n  ADD: d\n  UNSTAGED: e\n")

	stdout, _, err := runRootCommandIO(t, root, nil, "diff", "production/svc", "--semantic", "--json")
	if err != nil {
		t.Fatalf("diff --semantic failed: %v", err)
	}
	body := decodeJSON(t, stdout)
	want := map[string]string{"KEEP": "equal", "CHANGE": "equal", "ADD": "equal", "UNSTAGED": "added"}
	if got := jsonKeyField(t, body, "outcome"); !reflect.DeepEqual(got, want) {
		t.Fatalf("HEAD outcomes = %v, want %v", got, want)
	}
	if body["left"].(map[string]any)["revision"] != "HEAD" || body["right"].(map[string]any)["source"] != "worktree" {
		t.Fatalf("unexpected sides: %v", body)
	}

	stdout, _, err = runRootCommandIO(t, root, nil, "diff", "production/svc", "--semantic", "--to", first, "--json")
	if err != nil {
		t.Fatalf("diff --semantic --to failed: %v", err)
	}
	want = map[string]string{"KEEP": "equal", "CHANGE": "different", "DROP": "removed", "ADD": "added", "UNSTAGED": "added"}
	if got := jsonKeyField(t, decodeJSON(t, stdout), "outcome"); !reflect.DeepEqual(got, want) {
		t.Fatalf("revision outcomes = %v, want %v", got, want)
	}

	_, _, err = runRootCommandIO(t, root, nil, "diff", "production/svc", "--semantic", "--to", first, "--assert-equal")
	if err == nil || exitCodeOf(t, err) != 1 {
		t.Fatalf("expected --assert-equal to fail against the first revision, got %v", err)
	}
	_, _, err = runRootCommandIO(t, root, nil, "diff", "production/svc", "--semantic", "--to", first, "--assert-unequal")
	if err != nil {
		t.Fatalf("expected --assert-unequal to pass, got %v", err)
	}
}

func TestSemanticDiffTreatsAFileAddedSinceTheRevisionAsAllAdded(t *testing.T) {
	root := seedMutationRepo(t, defaultMutationSOPSRules, cliTestAgeKey)
	commitAll(t, root)
	putEncryptedDoc(t, root, "production/brand-new", "  A: x\n  B: \"\"\n")

	stdout, _, err := runRootCommandIO(t, root, nil, "diff", "production/brand-new", "--semantic")
	if err != nil {
		t.Fatalf("diff --semantic failed: %v", err)
	}
	for _, want := range []string{"A outcome=added left_state=missing right_state=present", "B outcome=added left_state=missing right_state=empty", "left name=production/brand-new source=revision revision=HEAD file_state=missing"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in:\n%s", want, stdout)
		}
	}

	_, _, err = runRootCommandIO(t, root, nil, "diff", "production/brand-new", "--semantic", "--to", "no-such-rev")
	if err == nil || exitCodeOf(t, err) != 1 {
		t.Fatalf("an unknown revision must fail, got %v", err)
	}
}

func TestFlaglessDiffStaysCiphertextAndNeedsNoAgeKey(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	t.Setenv("SOPS_AGE_KEY", "")
	root := seedKeysealRepo(t, false)
	writeFileForCLI(t, filepath.Join(root, "production/platform/app.enc.yaml"), "first\n")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-m", "seed")
	writeFileForCLI(t, filepath.Join(root, "production/platform/app.enc.yaml"), "second\n")

	stdout, stderr, err := runRootCommandIO(t, root, nil, "diff", "production/platform/app")
	if err != nil || stderr != "" {
		t.Fatalf("flagless diff failed: %v stderr=%q", err, stderr)
	}
	if !strings.Contains(stdout, "-first") || !strings.Contains(stdout, "+second") || strings.Contains(stdout, "outcome=") {
		t.Fatalf("expected a plain git diff:\n%s", stdout)
	}
}

func TestSemanticOnlyDiffFlagsRequireSemantic(t *testing.T) {
	root := seedKeysealRepo(t, false)

	for _, args := range [][]string{
		{"--json"}, {"--key", "A"}, {"--show-length"}, {"--show-type"}, {"--fingerprint"},
		{"--assert-equal"}, {"--assert-unequal"}, {"--to", "HEAD"},
	} {
		_, _, err := runRootCommandIO(t, root, nil, append([]string{"diff", "production/platform/app"}, args...)...)
		if err == nil || !strings.Contains(err.Error(), "requires --semantic") {
			t.Errorf("%v: expected a --semantic requirement, got %v", args, err)
		}
	}
}
