package mutate

import (
	"strings"
	"testing"
)

func TestReadSecretTrimsExactlyOneTrailingNewline(t *testing.T) {
	cases := map[string]string{
		"value":        "value",
		"value\n":      "value",
		"value\r\n":    "value",
		"value\n\n":    "value\n",
		"line1\nline2": "line1\nline2",
		"  spaced  \n": "  spaced  ",
	}
	for input, want := range cases {
		got, err := ReadSecret(strings.NewReader(input))
		if err != nil {
			t.Fatalf("ReadSecret(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("ReadSecret(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestReadSecretRejectsUnsafeInput(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"only newline": "\n",
		"invalid utf8": "\xff\xfe",
		"too large":    strings.Repeat("a", MaxSecretBytes+1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ReadSecret(strings.NewReader(input))
			if err == nil {
				t.Fatal("expected ReadSecret to fail")
			}
			if len(input) > 0 && strings.Contains(err.Error(), input) {
				t.Fatalf("error must not echo input: %v", err)
			}
		})
	}
}
