package mutate

import (
	"strings"
	"testing"
)

const documentFixture = `# top comment
version: 1
kind: env
name: production/app
description: Secrets for production/app
values:
  # database settings
  DB_HOST: db.internal # primary
  DB_PORT: "5432"
  APP_KEY: old
owner: platform
`

func TestDocumentEditsPreserveCommentsOrderAndExtraFields(t *testing.T) {
	doc, err := ParseDocument([]byte(documentFixture))
	if err != nil {
		t.Fatalf("ParseDocument returned error: %v", err)
	}

	if got := doc.Set("APP_KEY", "new"); got != Updated {
		t.Fatalf("Set existing = %q, want updated", got)
	}
	if got := doc.Set("DB_PORT", "5432"); got != Unchanged {
		t.Fatalf("Set same value = %q, want unchanged", got)
	}
	if got := doc.Set("NEW_FLAG", "true"); got != Added {
		t.Fatalf("Set new = %q, want added", got)
	}
	if !doc.Unset("DB_PORT") {
		t.Fatal("Unset existing key returned false")
	}
	if doc.Unset("MISSING") {
		t.Fatal("Unset missing key returned true")
	}
	doc.SetName("production/app-next")

	out, err := doc.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	text := string(out)
	for _, want := range []string{"# top comment", "# database settings", "# primary", "owner: platform", "name: production/app-next", `NEW_FLAG: "true"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, text)
		}
	}
	if strings.Contains(text, "DB_PORT") {
		t.Fatalf("expected DB_PORT to be removed, got:\n%s", text)
	}
	if strings.Index(text, "DB_HOST") > strings.Index(text, "APP_KEY") || strings.Index(text, "APP_KEY") > strings.Index(text, "NEW_FLAG") {
		t.Fatalf("expected existing key order with new keys appended, got:\n%s", text)
	}

	reparsed, err := ParseDocument(out)
	if err != nil {
		t.Fatalf("re-parse returned error: %v", err)
	}
	values := reparsed.Values()
	if values["APP_KEY"] != "new" || values["NEW_FLAG"] != "true" || values["DB_HOST"] != "db.internal" || len(values) != 3 {
		t.Fatalf("unexpected values after round trip: %v", values)
	}
}

func TestParseDocumentRejectsAmbiguousDocuments(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{name: "duplicate keys", body: "version: 1\nvalues:\n  A: one\n  A: two\n", want: "document has duplicate keys: A"},
		{name: "duplicate top-level values", body: "version: 1\nvalues:\n  A: one\nvalues:\n  B: two\n", want: "document has duplicate top-level keys: values"},
		{name: "missing values", body: "version: 1\nkind: env\n"},
		{name: "nested value", body: "version: 1\nvalues:\n  A:\n    nested: x\n"},
		{name: "not a mapping", body: "- a\n- b\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseDocument([]byte(tc.body))
			if err == nil {
				t.Fatal("expected ParseDocument to fail")
			}
			if tc.want != "" && err.Error() != tc.want {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

func TestUnencryptedValueKeysReportsOnlyPlaintextKeys(t *testing.T) {
	ciphertext := []byte("version: 1\nvalues:\n  SEALED: ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n  LEAKED: plaintext-marker\nsops:\n  version: 3.13.3\n")
	keys, err := unencryptedValueKeys(ciphertext)
	if err != nil {
		t.Fatalf("unencryptedValueKeys returned error: %v", err)
	}
	if len(keys) != 1 || keys[0] != "LEAKED" {
		t.Fatalf("expected only LEAKED, got %v", keys)
	}
	if strings.Contains(strings.Join(keys, ","), "plaintext-marker") {
		t.Fatal("result must not contain value text")
	}
	if _, err := unencryptedValueKeys([]byte("version: 1\nsops:\n  version: 3.13.3\n")); err == nil {
		t.Fatal("expected missing values mapping to fail")
	}
}

func TestSetMultilineValueRoundTrips(t *testing.T) {
	doc, err := ParseDocument([]byte("version: 1\nvalues:\n  A: x\n"))
	if err != nil {
		t.Fatalf("ParseDocument returned error: %v", err)
	}
	value := "-----BEGIN KEY-----\nabc: def # not a comment\n-----END KEY-----"
	doc.Set("PEM", value)
	out, err := doc.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	reparsed, err := ParseDocument(out)
	if err != nil {
		t.Fatalf("re-parse returned error: %v", err)
	}
	if got := reparsed.Values()["PEM"]; got != value {
		t.Fatalf("multiline value changed: got %q", got)
	}
}
