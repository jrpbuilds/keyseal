package contract_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/contract"
)

const defaultKeyPattern = `^[A-Z0-9_]+$`

func TestLoadFromConfigYAMLHappyPath(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`
version: 1
contracts:
  production-app:
    documents: [production/app]
    required: [APP_KEY]
    forbidden: [TWILIO_TOKEN]
    rules:
      - key: APP_KEY
        min_length: 8
      - key: TOKEN
        matches: "live_"
      - key: NOTE
        non_empty: true
      - equals:
          - key: APP_KEY
          - key: BACKUP_KEY
      - not_equals:
          - key: APP_KEY
          - key: SESSION_KEY
      - distinct: [APP_KEY, SESSION_KEY]
      - when:
          key: FEATURE
          equals: true
        require: [FEATURE_SECRET]
`)
	result, err := contract.LoadFromConfigYAML(body, dir, defaultKeyPattern)
	if err != nil {
		t.Fatalf("LoadFromConfigYAML returned error: %v", err)
	}
	if len(result.Problems) != 0 {
		t.Fatalf("unexpected problems: %#v", result.Problems)
	}
	def, ok := result.Contracts["production-app"]
	if !ok {
		t.Fatal("expected production-app contract")
	}
	if len(def.Rules) != 7 {
		t.Fatalf("expected 7 rules, got %d", len(def.Rules))
	}
	when := def.Rules[6]
	if when.WhenEquals != "true" {
		t.Fatalf("expected scalar text true, got %q", when.WhenEquals)
	}
}

func TestLoadFromConfigYAMLRejectsUnknownAndMixed(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		body    string
		want    string
		problem bool
	}{
		{
			name: "unknown field",
			body: `contracts:
  app:
    documents: [production/app]
    min_lenght: 32
`,
			want:    `unknown field "min_lenght"`,
			problem: true,
		},
		{
			name: "mixed operators",
			body: `contracts:
  app:
    documents: [production/app]
    rules:
      - key: APP_KEY
        min_length: 8
        matches: "^x"
`,
			want:    "exactly one of",
			problem: true,
		},
		{
			name: "bad regex",
			body: `contracts:
  app:
    documents: [production/app]
    rules:
      - key: APP_KEY
        matches: "("
`,
			want:    "invalid regex",
			problem: true,
		},
		{
			name: "min_length too small",
			body: `contracts:
  app:
    documents: [production/app]
    rules:
      - key: APP_KEY
        min_length: 0
`,
			want:    "min_length must be >= 1",
			problem: true,
		},
		{
			name: "non_empty false",
			body: `contracts:
  app:
    documents: [production/app]
    rules:
      - key: APP_KEY
        non_empty: false
`,
			want:    "non_empty must be true",
			problem: true,
		},
		{
			name: "required overlaps forbidden",
			body: `contracts:
  app:
    documents: [production/app]
    required: [APP_KEY]
    forbidden: [APP_KEY]
`,
			want:    "forbidden and also required",
			problem: true,
		},
		{
			name: "short equals",
			body: `contracts:
  app:
    documents: [production/app]
    rules:
      - equals:
          - key: APP_KEY
`,
			want:    "at least two",
			problem: true,
		},
		{
			name: "key outside pattern",
			body: `contracts:
  app:
    documents: [production/app]
    required: [app-key]
`,
			want:    "validation.key_pattern",
			problem: true,
		},
		{
			name: "invalid contract name",
			body: `contracts:
  "bad name":
    documents: [production/app]
`,
			want:    "invalid contract name",
			problem: true,
		},
		{
			name: "duplicate equals ref",
			body: `contracts:
  app:
    documents: [production/app]
    rules:
      - equals:
          - key: APP_KEY
          - key: APP_KEY
`,
			want:    "duplicate key ref",
			problem: true,
		},
		{
			name: "forbidden key also has min_length",
			body: `contracts:
  app:
    documents: [production/app]
    forbidden: [TOKEN]
    rules:
      - key: TOKEN
        min_length: 8
`,
			want:    "forbidden and also required",
			problem: true,
		},
		{
			name: "document not in list",
			body: `contracts:
  app:
    documents: [production/app]
    rules:
      - equals:
          - key: APP_KEY
          - document: production/other
            key: APP_KEY
`,
			want:    "not listed in documents",
			problem: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := contract.LoadFromConfigYAML([]byte(tt.body), dir, defaultKeyPattern)
			if err != nil {
				t.Fatalf("LoadFromConfigYAML returned error: %v", err)
			}
			if !tt.problem {
				return
			}
			if len(result.Problems) == 0 {
				t.Fatal("expected a problem")
			}
			if !strings.Contains(result.Problems[0].Message, tt.want) {
				t.Fatalf("expected %q in %#v", tt.want, result.Problems[0])
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contracts", "staging.yaml")
	if err := os.MkdirAll(filepath.Dir(contractPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(contractPath, []byte(`
documents: [staging/app]
required: [APP_KEY]
`), 0o600); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	body := []byte(`
contracts:
  staging-app:
    from: contracts/staging.yaml
`)
	result, err := contract.LoadFromConfigYAML(body, dir, defaultKeyPattern)
	if err != nil {
		t.Fatalf("LoadFromConfigYAML returned error: %v", err)
	}
	if len(result.Problems) != 0 {
		t.Fatalf("unexpected problems: %#v", result.Problems)
	}
	def := result.Contracts["staging-app"]
	if len(def.Documents) != 1 || def.Documents[0] != "staging/app" {
		t.Fatalf("unexpected definition: %#v", def)
	}
}

func TestLoadFromFileRejectsEscapeAndInlineMix(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "path traversal",
			body: `contracts:
  app:
    from: ../outside.yaml
`,
			want: "must not traverse",
		},
		{
			name: "absolute path",
			body: `contracts:
  app:
    from: /etc/passwd
`,
			want: "must be relative",
		},
		{
			name: "inline mix",
			body: `contracts:
  app:
    from: contracts/x.yaml
    documents: [production/app]
`,
			want: "cannot be combined",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := contract.LoadFromConfigYAML([]byte(tt.body), dir, defaultKeyPattern)
			if err != nil {
				t.Fatalf("LoadFromConfigYAML returned error: %v", err)
			}
			if len(result.Problems) == 0 {
				t.Fatal("expected a problem")
			}
			if !strings.Contains(result.Problems[0].Message, tt.want) {
				t.Fatalf("expected %q in %#v", tt.want, result.Problems[0])
			}
		})
	}
}

func TestLoadFromFileRejectsNestedFrom(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "contracts", "nested.yaml")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(nested, []byte("from: other.yaml\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	body := []byte(`
contracts:
  app:
    from: contracts/nested.yaml
`)
	result, err := contract.LoadFromConfigYAML(body, dir, defaultKeyPattern)
	if err != nil {
		t.Fatalf("LoadFromConfigYAML returned error: %v", err)
	}
	if len(result.Problems) == 0 || !strings.Contains(result.Problems[0].Message, "nested from") {
		t.Fatalf("expected nested from rejection, got %#v", result.Problems)
	}
}

func TestLoadFromFileRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "escape.yaml")
	if err := os.WriteFile(outsideFile, []byte("documents: [production/app]\n"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	linkDir := filepath.Join(dir, "contracts")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	linkPath := filepath.Join(linkDir, "escape.yaml")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	body := []byte(`
contracts:
  app:
    from: contracts/escape.yaml
`)
	result, err := contract.LoadFromConfigYAML(body, dir, defaultKeyPattern)
	if err != nil {
		t.Fatalf("LoadFromConfigYAML returned error: %v", err)
	}
	if len(result.Problems) == 0 {
		t.Fatal("expected symlink escape to fail")
	}
	if !strings.Contains(result.Problems[0].Message, "escapes config directory") {
		t.Fatalf("expected escape error, got %#v", result.Problems[0])
	}
}
