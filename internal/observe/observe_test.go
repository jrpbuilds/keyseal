package observe

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/config"
)

// Disposable age identities used only by these tests.
const (
	testAgeKey = `# public key: age1xlp99sh4c9dheuskt900y83mdcxdhjp0zhejf2l4lkh6fdzl0dsqsx4yrx
AGE-SECRET-KEY-1640MNDQ274MATFJR6D6R6GFW3FUDJLDUAM84TXRM9L70FUCEXV0QMEH0CE
`
	testAgePublicKey  = "age1xlp99sh4c9dheuskt900y83mdcxdhjp0zhejf2l4lkh6fdzl0dsqsx4yrx"
	otherAgePublicKey = "age18ky244sacp27ynw06qycnw0uk9ff55hs8fjm3532yty30zqjm35qmfqgpw"
	markerOne         = "kslobs-1c4e7a"
	markerTwo         = "kslobs-2b9d03"
)

type fixture struct {
	root  string
	scope *Scope
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops binary not available; skipping observe fixtures")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	root := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "keys.txt")
	writeFile(t, keyPath, testAgeKey)
	t.Setenv("SOPS_AGE_KEY_FILE", keyPath)
	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv(FingerprintKeyEnv, "")

	run(t, root, "git", "init", "-q")
	run(t, root, "git", "config", "user.name", "Keyseal Test")
	run(t, root, "git", "config", "user.email", "keyseal@example.com")
	return fixture{root: root, scope: New(root, config.Default(), root)}
}

func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
}

func envPlaintext(values string) string {
	return "version: 1\nkind: env\nname: test/doc\nvalues:\n" + values
}

// putEncrypted encrypts values for recipient with the real sops binary and
// writes the result at logical's encrypted path.
func (f fixture) putEncrypted(t *testing.T, logical, recipient, values string) {
	t.Helper()
	cmd := exec.Command("sops", "encrypt", "--filename-override", logical+".enc.yaml",
		"--input-type", "yaml", "--output-type", "yaml", "--age", recipient, "--encrypted-regex", "^(name|values)$")
	cmd.Stdin = strings.NewReader(envPlaintext(values))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("sops encrypt failed: %v", err)
	}
	writeFile(t, f.path(logical), string(out))
}

func (f fixture) path(logical string) string {
	return filepath.Join(f.root, filepath.FromSlash(logical)+".enc.yaml")
}

func (f fixture) commit(t *testing.T) {
	t.Helper()
	run(t, f.root, "git", "add", "-A")
	run(t, f.root, "git", "commit", "-q", "-m", "seed")
}

func jsonOf(t *testing.T, rep Report) map[string]any {
	t.Helper()
	body, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("MarshalJSON returned error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	return out
}

func everything(t *testing.T, rep Report) string {
	t.Helper()
	body, _ := json.Marshal(rep)
	return rep.Text() + string(body)
}

func keyOutcomes(t *testing.T, rep Report) map[string]string {
	t.Helper()
	out := map[string]string{}
	rows, _ := jsonOf(t, rep)["keys"].([]any)
	for _, row := range rows {
		m := row.(map[string]any)
		out[m["name"].(string)] = m["outcome"].(string)
	}
	return out
}

func TestInspectReportsStatesWithoutValues(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/app", testAgePublicKey, "  TOKEN: "+markerOne+"\n  BLANK: \"\"\n  NESTED:\n    k: "+markerTwo+"\n")

	rep := f.scope.Inspect(Ref{Logical: "prod/app"}, Option{ShowLength: true, ShowType: true})
	if !rep.Passed() {
		t.Fatalf("expected pass, got:\n%s", rep.Text())
	}
	got := jsonOf(t, rep)
	if got["file_state"] != "encrypted" || got["source"] != "worktree" || got["passed"] != true {
		t.Fatalf("unexpected header: %v", got)
	}
	states := map[string]string{}
	for _, row := range got["keys"].([]any) {
		m := row.(map[string]any)
		states[m["name"].(string)] = m["state"].(string)
	}
	want := map[string]string{"TOKEN": "present", "BLANK": "empty", "NESTED": "non_scalar"}
	if !reflect.DeepEqual(states, want) {
		t.Fatalf("states = %v, want %v", states, want)
	}
	for _, marker := range []string{markerOne, markerTwo} {
		if strings.Contains(everything(t, rep), marker) {
			t.Fatalf("value %q leaked into the report", marker)
		}
	}
	if !strings.Contains(rep.Text(), "TOKEN state=present length=13 type=str") {
		t.Fatalf("unexpected text:\n%s", rep.Text())
	}
}

func TestInspectKeyFilterListsMissingKeys(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/app", testAgePublicKey, "  A: x\n  B: y\n")

	rep := f.scope.Inspect(Ref{Logical: "prod/app"}, Option{Keys: []string{"B", "GONE"}})
	if !rep.Passed() {
		t.Fatalf("a missing key is a state, not a failure:\n%s", rep.Text())
	}
	if text := rep.Text(); !strings.Contains(text, "B state=present\n") || !strings.Contains(text, "GONE state=missing\n") || strings.Contains(text, "A state") {
		t.Fatalf("unexpected text:\n%s", text)
	}
}

func TestInspectEncryptedDocumentWithNoKeysIsAnEmptyListNotNull(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/empty", testAgePublicKey, "  {}\n")

	body := jsonOf(t, f.scope.Inspect(Ref{Logical: "prod/empty"}, Option{}))
	keys, ok := body["keys"].([]any)
	if !ok || len(keys) != 0 {
		t.Fatalf("expected keys: [], got %#v", body["keys"])
	}
}

func TestInspectFailsClosedOnFileStates(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.path("prod/placeholder"), " \n")
	writeFile(t, f.path("prod/plain"), envPlaintext("  TOKEN: "+markerOne+"\n"))

	for name, wantState := range map[string]string{"prod/placeholder": "placeholder", "prod/plain": "plaintext", "prod/absent": "missing"} {
		rep := f.scope.Inspect(Ref{Logical: name}, Option{})
		body := jsonOf(t, rep)
		if rep.Passed() || body["passed"] != false {
			t.Errorf("%s: expected failure", name)
		}
		if body["file_state"] != wantState {
			t.Errorf("%s: file_state = %v, want %s", name, body["file_state"], wantState)
		}
		if body["keys"] != nil {
			t.Errorf("%s: keys must be null, got %v", name, body["keys"])
		}
		if body["problem"] == nil || strings.Contains(everything(t, rep), markerOne) {
			t.Errorf("%s: want a problem and no plaintext content", name)
		}
	}
}

func TestInspectRejectsBadLogicalNameAndInvalidDocument(t *testing.T) {
	f := newFixture(t)
	if rep := f.scope.Inspect(Ref{Logical: "../escape"}, Option{}); rep.Passed() {
		t.Fatal("expected a traversing name to fail")
	}

	plaintext := "version: 2\nkind: env\nname: x\nvalues:\n  TOKEN: " + markerOne + "\n"
	cmd := exec.Command("sops", "encrypt", "--filename-override", "prod/v2.enc.yaml", "--input-type", "yaml", "--output-type", "yaml", "--age", testAgePublicKey, "--encrypted-regex", "^(name|values)$")
	cmd.Stdin = strings.NewReader(plaintext)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("sops encrypt failed: %v", err)
	}
	writeFile(t, f.path("prod/v2"), string(out))
	rep := f.scope.Inspect(Ref{Logical: "prod/v2"}, Option{})
	if rep.Passed() || !strings.Contains(rep.Text(), "is not a valid env document") || strings.Contains(everything(t, rep), markerOne) {
		t.Fatalf("unexpected report:\n%s", rep.Text())
	}
}

func TestDecryptFailureIsGenericAndKeepsStderrClean(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/foreign", otherAgePublicKey, "  TOKEN: "+markerOne+"\n")

	rep := f.scope.Inspect(Ref{Logical: "prod/foreign"}, Option{})
	if rep.Passed() {
		t.Fatal("expected a decrypt failure")
	}
	if got, want := jsonOf(t, rep)["problem"], `document "prod/foreign" could not be decrypted`; got != want {
		t.Fatalf("problem = %v, want %q", got, want)
	}
}

func TestInspectReadsRevisionNotWorktree(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/app", testAgePublicKey, "  OLD_ONLY: "+markerOne+"\n")
	f.commit(t)
	f.putEncrypted(t, "prod/app", testAgePublicKey, "  NEW_ONLY: "+markerTwo+"\n")

	rep := f.scope.Inspect(Ref{Logical: "prod/app", Revision: "HEAD"}, Option{})
	if !rep.Passed() || !strings.Contains(rep.Text(), "OLD_ONLY state=present") || strings.Contains(rep.Text(), "NEW_ONLY") {
		t.Fatalf("expected the committed document:\n%s", rep.Text())
	}
	if body := jsonOf(t, rep); body["source"] != "revision" || body["revision"] != "HEAD" {
		t.Fatalf("unexpected source: %v", body)
	}
}

func TestRevisionFailuresAreDistinct(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/app", testAgePublicKey, "  A: x\n")
	f.commit(t)

	unknown := f.scope.Inspect(Ref{Logical: "prod/app", Revision: "no-such-rev"}, Option{})
	if unknown.Passed() || !strings.Contains(unknown.Text(), `revision "no-such-rev" was not found`) {
		t.Fatalf("unknown revision:\n%s", unknown.Text())
	}
	if jsonOf(t, unknown)["file_state"] != nil {
		t.Fatal("an unknown revision has no file state")
	}

	absent := f.scope.Inspect(Ref{Logical: "prod/never", Revision: "HEAD"}, Option{})
	if absent.Passed() || jsonOf(t, absent)["file_state"] != "missing" {
		t.Fatalf("absent path should be missing:\n%s", absent.Text())
	}

	noGit := New(f.root, config.Default(), "").Inspect(Ref{Logical: "prod/app", Revision: "HEAD"}, Option{})
	if noGit.Passed() {
		t.Fatal("a revision needs a Git root")
	}
}

func TestCompareOutcomesAndAssertions(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/a", testAgePublicKey, "  SAME: "+markerOne+"\n  DIFF: "+markerOne+"\n  GONE: x\n")
	f.putEncrypted(t, "prod/b", testAgePublicKey, "  SAME: "+markerOne+"\n  DIFF: "+markerTwo+"\n  NEW: y\n")
	f.putEncrypted(t, "prod/twin", testAgePublicKey, "  SAME: "+markerOne+"\n  DIFF: "+markerOne+"\n  GONE: x\n")

	rep := f.scope.Compare(Ref{Logical: "prod/a"}, Ref{Logical: "prod/b"}, Option{})
	want := map[string]string{"SAME": "equal", "DIFF": "different", "GONE": "removed", "NEW": "added"}
	if got := keyOutcomes(t, rep); !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %v, want %v", got, want)
	}
	body := jsonOf(t, rep)
	if !rep.Passed() || body["equal"] != false || body["assertion"] != nil {
		t.Fatalf("a report-only comparison passes even when keys differ: %v", body)
	}
	for _, marker := range []string{markerOne, markerTwo} {
		if strings.Contains(everything(t, rep), marker) {
			t.Fatalf("value %q leaked", marker)
		}
	}

	cases := []struct {
		name          string
		left, right   string
		assertion     Assertion
		keys          []string
		wantPass      bool
		wantEqualJSON bool
	}{
		{"equal passes on twins", "prod/a", "prod/twin", AssertEqual, nil, true, true},
		{"equal fails on differing docs", "prod/a", "prod/b", AssertEqual, nil, false, false},
		{"equal on a selected equal key", "prod/a", "prod/b", AssertEqual, []string{"SAME"}, true, true},
		{"equal on a selected differing key", "prod/a", "prod/b", AssertEqual, []string{"DIFF"}, false, false},
		{"unequal passes on differing docs", "prod/a", "prod/b", AssertUnequal, nil, true, false},
		{"unequal fails on twins", "prod/a", "prod/twin", AssertUnequal, nil, false, true},
		{"unequal on a selected differing key", "prod/a", "prod/b", AssertUnequal, []string{"DIFF"}, true, false},
		{"equal fails when a requested key is missing from both", "prod/a", "prod/b", AssertEqual, []string{"SAME", "NOPE"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := f.scope.Compare(Ref{Logical: tc.left}, Ref{Logical: tc.right}, Option{Assertion: tc.assertion, Keys: tc.keys})
			body := jsonOf(t, rep)
			if rep.Passed() != tc.wantPass || body["passed"] != tc.wantPass {
				t.Fatalf("passed = %v, want %v:\n%s", rep.Passed(), tc.wantPass, rep.Text())
			}
			if body["equal"] != tc.wantEqualJSON {
				t.Fatalf("equal = %v, want %v", body["equal"], tc.wantEqualJSON)
			}
			if body["assertion"] != string(tc.assertion) {
				t.Fatalf("assertion = %v", body["assertion"])
			}
		})
	}
}

func TestCompareRequiresBothDocumentsUnlessMissingIsAllowed(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/a", testAgePublicKey, "  K: v\n  E: \"\"\n")

	strict := f.scope.Compare(Ref{Logical: "prod/a"}, Ref{Logical: "prod/absent"}, Option{})
	if strict.Passed() || jsonOf(t, strict)["keys"] != nil {
		t.Fatalf("a missing side fails a plain compare:\n%s", strict.Text())
	}

	lenient := f.scope.Compare(Ref{Logical: "prod/a"}, Ref{Logical: "prod/absent"}, Option{AllowMissing: true})
	want := map[string]string{"K": "removed", "E": "removed"}
	if !lenient.Passed() || !reflect.DeepEqual(keyOutcomes(t, lenient), want) {
		t.Fatalf("one missing side is allowed:\n%s", lenient.Text())
	}
	if jsonOf(t, lenient)["equal"] != false {
		t.Fatal("a missing document is never equal")
	}

	for _, assertion := range []Assertion{AssertEqual, AssertUnequal} {
		rep := f.scope.Compare(Ref{Logical: "prod/a"}, Ref{Logical: "prod/absent"}, Option{AllowMissing: true, Assertion: assertion})
		if rep.Passed() {
			t.Fatalf("assertion %s needs two encrypted documents", assertion)
		}
	}

	both := f.scope.Compare(Ref{Logical: "prod/x"}, Ref{Logical: "prod/y"}, Option{AllowMissing: true})
	if both.Passed() {
		t.Fatal("two missing documents must fail")
	}
}

func TestCompareClassifiesBothBeforeDecryptingEither(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.path("prod/placeholder"), "\n")
	f.putEncrypted(t, "prod/foreign", otherAgePublicKey, "  TOKEN: "+markerOne+"\n")

	rep := f.scope.Compare(Ref{Logical: "prod/placeholder"}, Ref{Logical: "prod/foreign"}, Option{})
	text := rep.Text()
	if rep.Passed() || !strings.Contains(text, "empty placeholder") {
		t.Fatalf("expected the placeholder failure:\n%s", text)
	}
	if strings.Contains(text, "could not be decrypted") {
		t.Fatalf("the sibling must not be decrypted after a classification failure:\n%s", text)
	}
}

func TestCompareInvalidAndUndecryptableSidesAreAttributed(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/ok", testAgePublicKey, "  A: x\n")
	f.putEncrypted(t, "prod/foreign", otherAgePublicKey, "  A: x\n")

	rep := f.scope.Compare(Ref{Logical: "prod/ok"}, Ref{Logical: "prod/foreign"}, Option{})
	body := jsonOf(t, rep)
	if rep.Passed() || body["right"].(map[string]any)["problem"] == nil || body["left"].(map[string]any)["problem"] != nil {
		t.Fatalf("expected a right-side decrypt failure only: %v", body)
	}
	if body["keys"] != nil {
		t.Fatal("no deltas may be invented after a failure")
	}
}

func TestCompareRevisionAgainstWorktree(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/app", testAgePublicKey, "  KEEP: "+markerOne+"\n  CHANGE: "+markerOne+"\n  DROP: x\n")
	f.commit(t)
	f.putEncrypted(t, "prod/app", testAgePublicKey, "  KEEP: "+markerOne+"\n  CHANGE: "+markerTwo+"\n  ADD: y\n")

	rep := f.scope.Compare(Ref{Logical: "prod/app", Revision: "HEAD"}, Ref{Logical: "prod/app"}, Option{AllowMissing: true})
	want := map[string]string{"KEEP": "equal", "CHANGE": "different", "DROP": "removed", "ADD": "added"}
	if got := keyOutcomes(t, rep); !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %v, want %v", got, want)
	}
	body := jsonOf(t, rep)
	if body["left"].(map[string]any)["source"] != "revision" || body["right"].(map[string]any)["source"] != "worktree" {
		t.Fatalf("unexpected sources: %v", body)
	}
}

func TestCompareNewWorktreeFileAgainstRevisionIsAllAdded(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/seed", testAgePublicKey, "  A: x\n")
	f.commit(t)
	f.putEncrypted(t, "prod/new", testAgePublicKey, "  A: x\n  B: \"\"\n")

	rep := f.scope.Compare(Ref{Logical: "prod/new", Revision: "HEAD"}, Ref{Logical: "prod/new"}, Option{AllowMissing: true})
	want := map[string]string{"A": "added", "B": "added"}
	if !rep.Passed() || !reflect.DeepEqual(keyOutcomes(t, rep), want) {
		t.Fatalf("a file added since the revision reads as all added:\n%s", rep.Text())
	}

	bad := f.scope.Compare(Ref{Logical: "prod/new", Revision: "nope"}, Ref{Logical: "prod/new"}, Option{AllowMissing: true})
	if bad.Passed() {
		t.Fatal("an unknown revision must fail even when missing is allowed")
	}
}

func TestFingerprintNeedsAValidKeyFile(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/a", testAgePublicKey, "  K: "+markerOne+"\n")
	short := filepath.Join(t.TempDir(), "short.key")
	writeFile(t, short, "too-short")

	for name, setup := range map[string]func(){
		"unset":   func() { t.Setenv(FingerprintKeyEnv, "") },
		"missing": func() { t.Setenv(FingerprintKeyEnv, filepath.Join(t.TempDir(), "nope")) },
		"short":   func() { t.Setenv(FingerprintKeyEnv, short) },
		"dir":     func() { t.Setenv(FingerprintKeyEnv, t.TempDir()) },
	} {
		setup()
		inspect := f.scope.Inspect(Ref{Logical: "prod/a"}, Option{Fingerprint: true})
		compare := f.scope.Compare(Ref{Logical: "prod/a"}, Ref{Logical: "prod/a"}, Option{Fingerprint: true})
		if inspect.Passed() || compare.Passed() {
			t.Errorf("%s: expected failure", name)
		}
		if strings.Contains(everything(t, inspect)+everything(t, compare), markerOne) {
			t.Errorf("%s: value leaked", name)
		}
	}
}

func TestFingerprintsAreKeyedAndEqualForEqualValues(t *testing.T) {
	f := newFixture(t)
	f.putEncrypted(t, "prod/a", testAgePublicKey, "  K: "+markerOne+"\n  E: \"\"\n")
	f.putEncrypted(t, "prod/b", testAgePublicKey, "  K: "+markerOne+"\n  E: \"\"\n")
	keyFile := filepath.Join(t.TempDir(), "mac.key")
	writeFile(t, keyFile, strings.Repeat("a", 32))
	t.Setenv(FingerprintKeyEnv, keyFile)

	fp := func() string {
		rep := f.scope.Inspect(Ref{Logical: "prod/a"}, Option{Fingerprint: true, Keys: []string{"K", "E"}})
		if !rep.Passed() {
			t.Fatalf("expected pass:\n%s", rep.Text())
		}
		rows := jsonOf(t, rep)["keys"].([]any)
		for _, row := range rows {
			m := row.(map[string]any)
			if m["name"] == "E" && m["fingerprint"] != nil {
				t.Fatal("an empty value is never fingerprinted")
			}
			if m["name"] == "K" {
				return m["fingerprint"].(string)
			}
		}
		t.Fatal("K missing")
		return ""
	}
	first := fp()
	if len(first) != 64 || strings.Contains(first, markerOne) {
		t.Fatalf("unexpected fingerprint %q", first)
	}
	writeFile(t, keyFile, strings.Repeat("b", 32))
	if fp() == first {
		t.Fatal("a different key must change the fingerprint")
	}

	cmp := f.scope.Compare(Ref{Logical: "prod/a"}, Ref{Logical: "prod/b"}, Option{Fingerprint: true, Assertion: AssertEqual})
	if !cmp.Passed() {
		t.Fatalf("expected equal documents:\n%s", cmp.Text())
	}
	if text := cmp.Text(); !strings.Contains(text, "left_fingerprint=") || !strings.Contains(text, "right_fingerprint=") {
		t.Fatalf("expected both fingerprints:\n%s", text)
	}
}

// SOPS refuses to encrypt duplicate keys, so the walk's duplicate detection is
// covered in redact and this test covers how reports surface the names.
func TestReportsSurfaceDuplicateKeyNames(t *testing.T) {
	ins := inspection{side: side{name: "prod/dup", source: sourceWorktree, fileState: "encrypted", duplicates: []string{"K"}, decrypted: true}}
	if !strings.Contains(ins.Text(), "duplicate_key=K") {
		t.Fatalf("expected a duplicate key line:\n%s", ins.Text())
	}
	if dupes := jsonOf(t, ins)["duplicate_keys"].([]any); len(dupes) != 1 || dupes[0] != "K" {
		t.Fatalf("unexpected duplicate_keys: %v", dupes)
	}

	cmp := comparison{left: ins.side, right: side{name: "prod/dup", source: sourceWorktree, fileState: "encrypted", decrypted: true}}
	if !strings.Contains(cmp.Text(), "left_duplicate_key=K") {
		t.Fatalf("expected a left duplicate key line:\n%s", cmp.Text())
	}
}

func TestReportTypesHaveNoValueBearingFields(t *testing.T) {
	forbidden := []string{"value", "values", "secret", "plaintext", "raw", "bytes", "ciphertext"}
	for _, typ := range []reflect.Type{reflect.TypeFor[inspection](), reflect.TypeFor[comparison](), reflect.TypeFor[side](), reflect.TypeFor[Option](), reflect.TypeFor[Scope]()} {
		for i := range typ.NumField() {
			if slices.Contains(forbidden, strings.ToLower(typ.Field(i).Name)) {
				t.Errorf("%s has value-bearing field %s", typ.Name(), typ.Field(i).Name)
			}
		}
	}
}
