package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/schema"
)

const (
	markerA = "kslmark-a91f3c"
	markerB = "kslmark-b27d5e"
)

func envDoc(values string) []byte {
	return []byte("version: 1\nkind: env\nname: test/doc\nvalues:\n" + values)
}

func plain(values string) Source { return Source{Plaintext: envDoc(values)} }

func mustProject(t *testing.T, values string, opt Options, mac []byte) Projection {
	t.Helper()
	p, err := Project(envDoc(values), opt, mac)
	if err != nil {
		t.Fatalf("Project returned error: %v", err)
	}
	return p
}

func stateOf(t *testing.T, p Projection, name string) KeyState {
	t.Helper()
	for _, key := range p.Keys {
		if key.Name() == name {
			return key.State()
		}
	}
	t.Fatalf("key %q not in projection", name)
	return ""
}

func TestProjectClassifiesKeyStates(t *testing.T) {
	p := mustProject(t, `  PRESENT: abc
  WHITESPACE: "  "
  EMPTY_QUOTED: ""
  EMPTY_NULL:
  WORD_NULL: null
  MAPPING:
    nested: `+markerA+`
  SEQUENCE:
    - `+markerA+`
  ANCHORED: &anchor `+markerA+`
  ALIASED: *anchor
`, Options{}, nil)

	// An alias is reported as non_scalar: the parsed node holds the anchor
	// name, not the aliased value, so claiming a scalar state would be a guess.
	want := map[string]KeyState{
		"PRESENT":      KeyPresent,
		"WHITESPACE":   KeyPresent,
		"EMPTY_QUOTED": KeyEmpty,
		"EMPTY_NULL":   KeyEmpty,
		"WORD_NULL":    KeyPresent,
		"MAPPING":      KeyNonScalar,
		"SEQUENCE":     KeyNonScalar,
		"ANCHORED":     KeyPresent,
		"ALIASED":      KeyNonScalar,
	}
	if len(p.Keys) != len(want) {
		t.Fatalf("expected %d keys, got %d", len(want), len(p.Keys))
	}
	for name, state := range want {
		if got := stateOf(t, p, name); got != state {
			t.Errorf("%s: expected %s, got %s", name, state, got)
		}
	}
}

func TestProjectSelectedKeysReportMissingAndSkipOthers(t *testing.T) {
	p := mustProject(t, "  A: one\n  B: two\n", Options{Keys: []string{"B", "NOPE", "B"}}, nil)
	if len(p.Keys) != 2 || p.Keys[0].Name() != "B" || p.Keys[1].Name() != "NOPE" {
		t.Fatalf("unexpected keys: %+v", p.Keys)
	}
	if p.Keys[1].State() != KeyMissing {
		t.Fatalf("expected NOPE missing, got %s", p.Keys[1].State())
	}
}

func TestProjectEmptyMappingIsAnEmptyNonNilList(t *testing.T) {
	p, err := Project([]byte("version: 1\nkind: env\nvalues: {}\n"), Options{}, nil)
	if err != nil {
		t.Fatalf("Project returned error: %v", err)
	}
	if p.Keys == nil || len(p.Keys) != 0 {
		t.Fatalf("expected a non-nil empty list, got %#v", p.Keys)
	}
}

func TestProjectMetadataIsOptInAndOnlyForScalars(t *testing.T) {
	values := "  S: héllo\n  I: 42\n  B: true\n  N: null\n  E: \"\"\n  EN:\n  M:\n    k: v\n"
	plainKeys := mustProject(t, values, Options{}, nil)
	for _, key := range plainKeys.Keys {
		if key.ann != (Annotation{}) {
			t.Fatalf("%s: metadata must be absent unless requested, got %+v", key.Name(), key.ann)
		}
	}

	p := mustProject(t, values, Options{ShowLength: true, ShowType: true}, nil)
	byName := map[string]Key{}
	for _, key := range p.Keys {
		byName[key.Name()] = key
	}
	wantTypes := map[string]ValueType{"S": TypeStr, "I": TypeInt, "B": TypeBool, "N": TypeNull, "E": TypeStr, "EN": TypeNull, "M": TypeNonScalar}
	for name, typ := range wantTypes {
		if got := byName[name].ann.Type; got != typ {
			t.Errorf("%s: expected type %s, got %s", name, typ, got)
		}
	}
	if got := *byName["S"].ann.Length; got != 5 {
		t.Errorf("length counts runes, expected 5 got %d", got)
	}
	if got := *byName["EN"].ann.Length; got != 0 {
		t.Errorf("empty scalar length should be 0, got %d", got)
	}
	if byName["M"].ann.Length != nil {
		t.Error("non-scalar must not report a length")
	}
}

func TestFingerprintOnlyForPresentScalarsAndIsDomainSeparated(t *testing.T) {
	mac := []byte(strings.Repeat("k", 32))
	p := mustProject(t, "  PRESENT: "+markerA+"\n  EMPTY: \"\"\n  MAP:\n    k: v\n", Options{Keys: []string{"PRESENT", "EMPTY", "MAP", "GONE"}}, mac)
	for _, key := range p.Keys {
		has := key.ann.Fingerprint != ""
		if has != (key.Name() == "PRESENT") {
			t.Errorf("%s: fingerprint presence = %v", key.Name(), has)
		}
	}

	plainMAC := hmac.New(sha256.New, mac)
	plainMAC.Write([]byte(markerA))
	unseparated := hex.EncodeToString(plainMAC.Sum(nil))
	unkeyed := sha256.Sum256([]byte(markerA))

	got := fingerprint(mac, markerA)
	separated := hmac.New(sha256.New, mac)
	separated.Write([]byte("keyseal-fingerprint-v1\x00" + markerA))
	if want := hex.EncodeToString(separated.Sum(nil)); got != want {
		t.Fatalf("fingerprint is not HMAC-SHA256 over the domain prefix and value")
	}
	if got == unseparated || got == hex.EncodeToString(unkeyed[:]) {
		t.Fatal("fingerprint must be keyed and domain separated")
	}
	if fingerprint([]byte(strings.Repeat("z", 32)), markerA) == got {
		t.Fatal("fingerprint must depend on the key")
	}
}

func TestReportsNeverContainValues(t *testing.T) {
	mac := []byte(strings.Repeat("m", 32))
	values := "  A: " + markerA + "\n  B: " + markerB + "\n  C:\n    nested: " + markerA + "\n"
	opt := Options{ShowLength: true, ShowType: true}

	p := mustProject(t, values, opt, mac)
	cmp, err := CompareYAML(plain(values), plain("  A: "+markerB+"\n  B: "+markerB+"\n"), opt, mac)
	if err != nil {
		t.Fatalf("CompareYAML returned error: %v", err)
	}

	var out strings.Builder
	for _, key := range p.Keys {
		body, _ := json.Marshal(key)
		out.WriteString(key.Line() + string(body) + fmt.Sprintf("%v%+v%#v", key, key, key))
	}
	for _, delta := range cmp.Deltas {
		body, _ := json.Marshal(delta)
		out.WriteString(delta.Line() + string(body) + fmt.Sprintf("%v%+v%#v", delta, delta, delta))
	}
	for _, marker := range []string{markerA, markerB} {
		if strings.Contains(out.String(), marker) {
			t.Fatalf("value %q leaked into report output", marker)
		}
	}
}

func TestReportTypesHaveNoValueBearingFields(t *testing.T) {
	forbidden := []string{"value", "values", "secret", "plaintext", "raw", "bytes"}
	for _, typ := range []reflect.Type{
		reflect.TypeFor[Key](), reflect.TypeFor[Delta](), reflect.TypeFor[Annotation](),
		reflect.TypeFor[Projection](), reflect.TypeFor[Comparison](), reflect.TypeFor[Options](),
	} {
		for i := range typ.NumField() {
			if name := strings.ToLower(typ.Field(i).Name); slices.Contains(forbidden, name) {
				t.Errorf("%s has value-bearing field %s", typ.Name(), typ.Field(i).Name)
			}
		}
	}
}

func TestDuplicateKeysMatchSchemaParser(t *testing.T) {
	values := "  A: one\n  B: x\n  A: two\n  C: y\n  B: z\n  A: three\n"
	p := mustProject(t, values, Options{}, nil)
	_, want, err := schema.ParseYAMLDocument(envDoc(values))
	if err != nil {
		t.Fatalf("ParseYAMLDocument returned error: %v", err)
	}
	if !slices.Equal(p.Duplicates, want) {
		t.Fatalf("duplicates = %v, schema parser = %v", p.Duplicates, want)
	}
}

func TestEmptyVersusPresentAgreesWithSchemaParser(t *testing.T) {
	values := "  EMPTY: \"\"\n  NULLISH:\n  SPACE: \" \"\n  FULL: x\n"
	doc, _, err := schema.ParseYAMLDocument(envDoc(values))
	if err != nil {
		t.Fatalf("ParseYAMLDocument returned error: %v", err)
	}
	p := mustProject(t, values, Options{}, nil)
	for _, key := range p.Keys {
		stored := doc.Values[key.Name()]
		if (key.State() == KeyEmpty) != (stored == "") {
			t.Errorf("%s: state %s disagrees with stored %q", key.Name(), key.State(), stored)
		}
	}
}

func TestInvalidDocumentsFailWithoutQuotingContent(t *testing.T) {
	for name, doc := range map[string]string{
		"not yaml":        "{: [" + markerA,
		"scalar root":     markerA,
		"list root":       "- " + markerA,
		"wrong version":   "version: 2\nkind: env\nvalues:\n  A: " + markerA + "\n",
		"wrong kind":      "version: 1\nkind: other\nvalues:\n  A: " + markerA + "\n",
		"missing values":  "version: 1\nkind: env\n",
		"values scalar":   "version: 1\nkind: env\nvalues: " + markerA + "\n",
		"values null":     "version: 1\nkind: env\nvalues:\n",
		"complex key":     "version: 1\nkind: env\nvalues:\n  ? [" + markerA + "]\n  : x\n",
		"missing header":  "values:\n  A: " + markerA + "\n",
		"values sequence": "version: 1\nkind: env\nvalues:\n  - " + markerA + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Project([]byte(doc), Options{}, nil)
			if !errors.Is(err, ErrInvalidDocument) {
				t.Fatalf("expected ErrInvalidDocument, got %v", err)
			}
			if strings.Contains(err.Error(), markerA) {
				t.Fatal("error must not quote document content")
			}
		})
	}
}

func outcomes(t *testing.T, cmp Comparison) map[string]Outcome {
	t.Helper()
	out := map[string]Outcome{}
	for _, d := range cmp.Deltas {
		out[d.Name()] = d.Outcome()
	}
	return out
}

func TestCompareYAMLOutcomes(t *testing.T) {
	left := plain("  SAME: " + markerA + "\n  DIFF: " + markerA + "\n  GONE: x\n  BOTH_EMPTY: \"\"\n  EMPTY_VS_FULL: \"\"\n  SPACE_VS_EMPTY: \" \"\n  MAP_A:\n    k: v\n  MAP_B:\n    k: v\n  MAP_VS_SCALAR:\n    k: v\n  NULL_WORD: null\n")
	right := plain("  SAME: " + markerA + "\n  DIFF: " + markerB + "\n  NEW: y\n  BOTH_EMPTY: \"\"\n  EMPTY_VS_FULL: z\n  SPACE_VS_EMPTY: \"\"\n  MAP_A:\n    k: v\n  MAP_B:\n    k: other\n  MAP_VS_SCALAR: s\n  NULL_WORD: \"null\"\n")

	cmp, err := CompareYAML(left, right, Options{}, nil)
	if err != nil {
		t.Fatalf("CompareYAML returned error: %v", err)
	}
	want := map[string]Outcome{
		"SAME":           OutcomeEqual,
		"DIFF":           OutcomeDifferent,
		"GONE":           OutcomeRemoved,
		"NEW":            OutcomeAdded,
		"BOTH_EMPTY":     OutcomeEqual,
		"EMPTY_VS_FULL":  OutcomeDifferent,
		"SPACE_VS_EMPTY": OutcomeDifferent,
		"MAP_A":          OutcomeDifferent,
		"MAP_B":          OutcomeDifferent,
		"MAP_VS_SCALAR":  OutcomeDifferent,
		"NULL_WORD":      OutcomeEqual,
	}
	got := outcomes(t, cmp)
	for name, outcome := range want {
		if got[name] != outcome {
			t.Errorf("%s: expected %s, got %s", name, outcome, got[name])
		}
	}
	if len(got) != len(want) {
		t.Errorf("expected %d deltas, got %d", len(want), len(got))
	}
	names := make([]string, len(cmp.Deltas))
	for i, d := range cmp.Deltas {
		names[i] = d.Name()
	}
	if !slices.IsSorted(names) {
		t.Errorf("deltas must be sorted by name, got %v", names)
	}
}

func TestCompareYAMLEmptyIsNotMissing(t *testing.T) {
	cmp, err := CompareYAML(plain("  K: \"\"\n"), plain("  OTHER: x\n"), Options{}, nil)
	if err != nil {
		t.Fatalf("CompareYAML returned error: %v", err)
	}
	got := outcomes(t, cmp)
	if got["K"] != OutcomeRemoved || got["OTHER"] != OutcomeAdded {
		t.Fatalf("empty must read as present on its side, got %v", got)
	}
}

func TestCompareYAMLAbsentSideHasNoKeys(t *testing.T) {
	cmp, err := CompareYAML(Source{Absent: true}, plain("  A: x\n  B: \"\"\n"), Options{}, nil)
	if err != nil {
		t.Fatalf("CompareYAML returned error: %v", err)
	}
	got := outcomes(t, cmp)
	if got["A"] != OutcomeAdded || got["B"] != OutcomeAdded || len(got) != 2 {
		t.Fatalf("unexpected outcomes: %v", got)
	}

	both, err := CompareYAML(Source{Absent: true}, Source{Absent: true}, Options{}, nil)
	if err != nil || both.Deltas == nil || len(both.Deltas) != 0 {
		t.Fatalf("two absent sources compare as an empty, non-nil list, got %#v, %v", both.Deltas, err)
	}
}

func TestCompareYAMLKeyFilterAndMissingFromBoth(t *testing.T) {
	cmp, err := CompareYAML(plain("  A: 1\n  B: 2\n"), plain("  A: 1\n  B: 3\n"), Options{Keys: []string{"A", "NOPE", "A", "ALSO_NOPE"}}, nil)
	if err != nil {
		t.Fatalf("CompareYAML returned error: %v", err)
	}
	if got := outcomes(t, cmp); len(got) != 1 || got["A"] != OutcomeEqual {
		t.Fatalf("filter should keep only A, got %v", got)
	}
	if !slices.Equal(cmp.MissingFromBoth, []string{"ALSO_NOPE", "NOPE"}) {
		t.Fatalf("unexpected missing-from-both: %v", cmp.MissingFromBoth)
	}
}

func TestCompareYAMLMetadataDoesNotChangeOutcome(t *testing.T) {
	mac := []byte(strings.Repeat("q", 32))
	left, right := plain("  A: \"1\"\n  B: x\n"), plain("  A: 1\n  B: x\n")
	base, err := CompareYAML(left, right, Options{}, nil)
	if err != nil {
		t.Fatalf("CompareYAML returned error: %v", err)
	}
	rich, err := CompareYAML(left, right, Options{ShowLength: true, ShowType: true}, mac)
	if err != nil {
		t.Fatalf("CompareYAML returned error: %v", err)
	}
	if !reflect.DeepEqual(outcomes(t, base), outcomes(t, rich)) {
		t.Fatal("metadata flags changed an outcome")
	}
	a := rich.Deltas[0]
	if a.leftAnn.Type != TypeStr || a.rightAnn.Type != TypeInt {
		t.Fatalf("type metadata should distinguish \"1\" from 1, got %s and %s", a.leftAnn.Type, a.rightAnn.Type)
	}
	if a.leftAnn.Fingerprint != a.rightAnn.Fingerprint || a.leftAnn.Fingerprint == "" {
		t.Fatal("equal text must produce equal fingerprints across sides")
	}
}

func TestCompareYAMLAttributesInvalidSide(t *testing.T) {
	for name, tc := range map[string]struct {
		left, right Source
		wantRight   bool
	}{
		"left":  {Source{Plaintext: []byte("nope")}, plain("  A: x\n"), false},
		"right": {plain("  A: x\n"), Source{Plaintext: []byte("version: 1\nkind: env\n")}, true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CompareYAML(tc.left, tc.right, Options{}, nil)
			var side InvalidSideError
			if !errors.As(err, &side) || side.Right != tc.wantRight || !errors.Is(err, ErrInvalidDocument) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCompareYAMLReportsDuplicatesPerSide(t *testing.T) {
	cmp, err := CompareYAML(plain("  A: 1\n  A: 2\n"), plain("  B: 1\n  B: 2\n"), Options{}, nil)
	if err != nil {
		t.Fatalf("CompareYAML returned error: %v", err)
	}
	if !slices.Equal(cmp.LeftDuplicates, []string{"A"}) || !slices.Equal(cmp.RightDuplicates, []string{"B"}) {
		t.Fatalf("unexpected duplicates: %v %v", cmp.LeftDuplicates, cmp.RightDuplicates)
	}
}

func TestNewKeyAndNewDeltaRejectContradictions(t *testing.T) {
	one := 1
	for name, fn := range map[string]func() error{
		"empty name":             func() error { _, err := NewKey("", KeyPresent, Annotation{}); return err },
		"unknown state":          func() error { _, err := NewKey("A", "bogus", Annotation{}); return err },
		"length on missing":      func() error { _, err := NewKey("A", KeyMissing, Annotation{Length: &one}); return err },
		"fingerprint on missing": func() error { _, err := NewKey("A", KeyMissing, Annotation{Fingerprint: "ab"}); return err },
		"length on non_scalar":   func() error { _, err := NewKey("A", KeyNonScalar, Annotation{Length: &one}); return err },
		"fingerprint on empty":   func() error { _, err := NewKey("A", KeyEmpty, Annotation{Fingerprint: "ab"}); return err },
		"unknown type":           func() error { _, err := NewKey("A", KeyPresent, Annotation{Type: "weird"}); return err },
		"added with left present": func() error {
			_, err := NewDelta("A", OutcomeAdded, KeyPresent, KeyPresent, Annotation{}, Annotation{})
			return err
		},
		"removed with right present": func() error {
			_, err := NewDelta("A", OutcomeRemoved, KeyPresent, KeyPresent, Annotation{}, Annotation{})
			return err
		},
		"equal with a missing side": func() error {
			_, err := NewDelta("A", OutcomeEqual, KeyMissing, KeyPresent, Annotation{}, Annotation{})
			return err
		},
		"equal non_scalar": func() error {
			_, err := NewDelta("A", OutcomeEqual, KeyNonScalar, KeyNonScalar, Annotation{}, Annotation{})
			return err
		},
		"different with missing": func() error {
			_, err := NewDelta("A", OutcomeDifferent, KeyMissing, KeyPresent, Annotation{}, Annotation{})
			return err
		},
	} {
		if err := fn(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestTextNamesCannotForgeFields(t *testing.T) {
	key, err := NewKey("A state=present\nB", KeyPresent, Annotation{})
	if err != nil {
		t.Fatalf("NewKey returned error: %v", err)
	}
	if strings.Contains(key.Line(), "\n") || !strings.HasPrefix(key.Line(), `"A state=present\nB"`) {
		t.Fatalf("name should be quoted, got %q", key.Line())
	}
}
