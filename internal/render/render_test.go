package render_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/render"
	"github.com/jrpbuilds/keyseal/internal/schema"
)

func TestMergeEnvDocsLaterFilesWin(t *testing.T) {
	docs := []schema.EnvSecretDocument{
		{Values: map[string]string{"APP_ENV": "staging", "DB_HOST": "db-a"}},
		{Values: map[string]string{"APP_ENV": "production"}},
	}
	merged := render.MergeEnvDocs(docs)
	if merged["APP_ENV"] != "production" {
		t.Fatalf("expected later value to win, got %q", merged["APP_ENV"])
	}
	if merged["DB_HOST"] != "db-a" {
		t.Fatalf("expected DB_HOST to be preserved")
	}
}

func TestRenderDotenv(t *testing.T) {
	out, err := render.RenderDotenv(map[string]string{
		"APP_ENV": "production",
		"MULTI":   "hello\n\"quoted\"",
	})
	if err != nil {
		t.Fatalf("RenderDotenv returned error: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "APP_ENV=\"production\"") {
		t.Fatalf("expected dotenv output to include APP_ENV, got %q", got)
	}
	if !strings.Contains(got, "MULTI=\"hello\\n\\\"quoted\\\"\"") {
		t.Fatalf("expected escaped multiline value, got %q", got)
	}
}

func TestRenderJSON(t *testing.T) {
	out, err := render.RenderJSON(map[string]string{"APP_ENV": "production"})
	if err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}
	if !strings.Contains(string(out), "\"APP_ENV\": \"production\"") {
		t.Fatalf("unexpected json output: %q", string(out))
	}
}

func TestRenderYAML(t *testing.T) {
	out, err := render.RenderYAML(map[string]string{"DB_HOST": "db", "APP_ENV": "production"})
	if err != nil {
		t.Fatalf("RenderYAML returned error: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "APP_ENV: production") || !strings.Contains(got, "DB_HOST: db") {
		t.Fatalf("unexpected yaml output: %q", string(out))
	}
	if strings.Index(got, "APP_ENV") > strings.Index(got, "DB_HOST") {
		t.Fatalf("expected yaml output to be sorted, got %q", got)
	}
}

func TestSelectPresentAndMissing(t *testing.T) {
	values := map[string]string{
		"APP_ENV":    "production",
		"DB_HOST":    "db",
		"BLANK":      "",
		"ONLY_EARLY": "kept",
	}
	selected, missing := render.Select(values, []string{"BLANK", "MISSING_B", "APP_ENV", "MISSING_A"})
	if !reflect.DeepEqual(selected, map[string]string{"BLANK": "", "APP_ENV": "production"}) {
		t.Fatalf("unexpected selected map: %#v", selected)
	}
	if !reflect.DeepEqual(missing, []string{"MISSING_B", "MISSING_A"}) {
		t.Fatalf("expected missing names in request order, got %#v", missing)
	}
}

func TestSelectLaterMergeWinner(t *testing.T) {
	merged := render.MergeEnvDocs([]schema.EnvSecretDocument{
		{Values: map[string]string{"APP_ENV": "staging", "DB_HOST": "db-a"}},
		{Values: map[string]string{"APP_ENV": "production"}},
	})
	selected, missing := render.Select(merged, []string{"APP_ENV", "DB_HOST"})
	if len(missing) != 0 {
		t.Fatalf("expected no missing keys, got %#v", missing)
	}
	if selected["APP_ENV"] != "production" {
		t.Fatalf("expected later merge winner, got %q", selected["APP_ENV"])
	}
	if selected["DB_HOST"] != "db-a" {
		t.Fatalf("expected earlier-only key to remain selectable, got %q", selected["DB_HOST"])
	}
}

func TestSelectReturnsIndependentMap(t *testing.T) {
	values := map[string]string{"APP_ENV": "production", "DB_HOST": "db"}
	selected, _ := render.Select(values, []string{"APP_ENV"})
	selected["APP_ENV"] = "mutated"
	selected["NEW"] = "added"
	if values["APP_ENV"] != "production" {
		t.Fatalf("Select must not mutate the input map values, got %q", values["APP_ENV"])
	}
	if _, ok := values["NEW"]; ok {
		t.Fatal("Select must return an independent map")
	}
	if _, ok := selected["DB_HOST"]; ok {
		t.Fatal("selected map must not include unselected keys")
	}
}
