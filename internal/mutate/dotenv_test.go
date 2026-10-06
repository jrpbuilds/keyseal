package mutate

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/render"
)

func TestReadDotenvFileEnforcesSizeCap(t *testing.T) {
	dir := t.TempDir()
	normal := filepath.Join(dir, "normal.env")
	if err := os.WriteFile(normal, []byte("A=one\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	got, err := ReadDotenvFile(normal)
	if err != nil {
		t.Fatalf("ReadDotenvFile returned error: %v", err)
	}
	if got["A"] != "one" {
		t.Fatalf("unexpected values: %v", got)
	}

	oversize := filepath.Join(dir, "oversize.env")
	body := "A=" + strings.Repeat("x", MaxEnvFileBytes)
	if err := os.WriteFile(oversize, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if _, err := ReadDotenvFile(oversize); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("expected oversize env file to fail, got %v", err)
	}
}

func TestParseDotenvSupportedForms(t *testing.T) {
	input := strings.Join([]string{
		"# intake from provider",
		"",
		"RAW=abc#def ghi",
		"export EXPORTED=yes",
		`DOUBLE="say \"hi\"\nnext\\line"`,
		`SINGLE='literal \n kept'`,
		"SPACED = padded value \r",
		"EMPTY=",
	}, "\n")
	got, err := ParseDotenv([]byte(input))
	if err != nil {
		t.Fatalf("ParseDotenv returned error: %v", err)
	}
	want := map[string]string{
		"RAW":      "abc#def ghi",
		"EXPORTED": "yes",
		"DOUBLE":   "say \"hi\"\nnext\\line",
		"SINGLE":   `literal \n kept`,
		"SPACED":   "padded value",
		"EMPTY":    "",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("ParseDotenv = %#v, want %#v", got, want)
	}
}

func TestParseDotenvRoundTripsKeysealRender(t *testing.T) {
	values := map[string]string{
		"A": `quote " backslash \ newline` + "\n" + "end",
		"B": "plain",
		"C": "#hash = equals",
	}
	rendered, err := render.RenderDotenv(values)
	if err != nil {
		t.Fatalf("RenderDotenv returned error: %v", err)
	}
	got, err := ParseDotenv(rendered)
	if err != nil {
		t.Fatalf("ParseDotenv returned error: %v", err)
	}
	if !maps.Equal(got, values) {
		t.Fatalf("round trip = %#v, want %#v", got, values)
	}
}

func TestParseDotenvErrorsDoNotEchoValues(t *testing.T) {
	const secret = "s3cr3t-marker"
	cases := map[string]string{
		"no equals":         "OK=1\n" + secret,
		"unterminated":      `KEY="` + secret,
		"unknown escape":    `KEY="` + secret + `\t"`,
		"unescaped quote":   `KEY="` + secret + `"x"`,
		"single with quote": `KEY='` + secret + `'x'`,
		"duplicate key":     secret + "=a\n" + secret + "=b",
		"duplicate value":   "KEY=a\nKEY=" + secret,
		"invalid key":       "BAD KEY=" + secret,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDotenv([]byte(input))
			if err == nil {
				t.Fatal("expected ParseDotenv to fail")
			}
			if !strings.Contains(err.Error(), "line ") {
				t.Fatalf("expected a line number in error, got %v", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error must not echo values: %v", err)
			}
		})
	}
}
