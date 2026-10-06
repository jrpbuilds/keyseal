package mutate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// MaxEnvFileBytes caps how much of an env file import will read.
const MaxEnvFileBytes = 1 << 20

// ReadDotenvFile reads and parses an env file of at most MaxEnvFileBytes.
func ReadDotenvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read env file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxEnvFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read env file: %w", err)
	}
	if len(data) > MaxEnvFileBytes {
		return nil, fmt.Errorf("env file is larger than %d bytes", MaxEnvFileBytes)
	}
	return ParseDotenv(data)
}

// ParseDotenv parses a dotenv file into key/value pairs.
//
// Supported forms are blank lines, `#` comment lines, an optional `export `
// prefix, `KEY=raw`, `KEY="..."` with the escapes Keyseal's own dotenv render
// emits (\\, \n, \"), and `KEY='...'` literals. Unquoted values are taken
// verbatim to the end of the line because secrets may contain `#`.
//
// Errors report line numbers only so malformed input never echoes values.
func ParseDotenv(data []byte) (map[string]string, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("env file must be valid UTF-8 text")
	}
	values := map[string]string{}
	firstLine := map[string]int{}
	for i, line := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimSpace(rest)
		}
		rawKey, rawValue, ok := strings.Cut(line, "=")
		key := strings.TrimSpace(rawKey)
		if !ok || key == "" || strings.ContainsAny(key, " \t\"'") {
			return nil, fmt.Errorf("env file line %d: expected KEY=value", lineNo)
		}
		value, err := parseDotenvValue(strings.TrimSpace(rawValue))
		if err != nil {
			return nil, fmt.Errorf("env file line %d: %w", lineNo, err)
		}
		if first, seen := firstLine[key]; seen {
			return nil, fmt.Errorf("env file line %d: duplicate key (first defined on line %d)", lineNo, first)
		}
		firstLine[key] = lineNo
		values[key] = value
	}
	return values, nil
}

func parseDotenvValue(raw string) (string, error) {
	switch {
	case strings.HasPrefix(raw, `"`):
		if len(raw) < 2 || !strings.HasSuffix(raw, `"`) {
			return "", errors.New("unterminated double-quoted value")
		}
		return unescapeDoubleQuoted(raw[1 : len(raw)-1])
	case strings.HasPrefix(raw, "'"):
		if len(raw) < 2 || !strings.HasSuffix(raw, "'") {
			return "", errors.New("unterminated single-quoted value")
		}
		inner := raw[1 : len(raw)-1]
		if strings.Contains(inner, "'") {
			return "", errors.New("single-quoted value contains a quote")
		}
		return inner, nil
	default:
		return raw, nil
	}
}

// unescapeDoubleQuoted reverses the escaping used by render.RenderDotenv and
// rejects anything else so ambiguous input fails instead of being guessed.
func unescapeDoubleQuoted(inner string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch c {
		case '"':
			return "", errors.New("double-quoted value contains an unescaped quote")
		case '\\':
			if i+1 >= len(inner) {
				return "", errors.New("double-quoted value ends with a backslash")
			}
			i++
			switch inner[i] {
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case '"':
				b.WriteByte('"')
			default:
				return "", errors.New("double-quoted value contains an unsupported escape")
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}
