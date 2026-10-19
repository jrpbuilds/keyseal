package contract

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jrpbuilds/keyseal/internal/render"
	"github.com/jrpbuilds/keyseal/internal/schema"
)

// Evaluate checks def against already-decrypted documents keyed by logical
// name. It never logs or returns secret values.
//
// Callers must supply every document listed in def.Documents. Missing map
// entries are treated as an operational load failure and rules are skipped.
func Evaluate(def Definition, docs map[string]schema.EnvSecretDocument) []Violation {
	ordered := make([]schema.EnvSecretDocument, 0, len(def.Documents))
	for _, logical := range def.Documents {
		doc, ok := docs[logical]
		if !ok {
			return []Violation{{
				Rule:    string(RuleLoad),
				Keys:    []string{},
				Message: formatMessage(RuleLoad, nil, "document %q is unavailable", logical),
			}}
		}
		ordered = append(ordered, doc)
	}
	merged := render.MergeEnvDocs(ordered)

	var violations []Violation
	for _, key := range def.Required {
		if _, ok := merged[key]; !ok {
			violations = append(violations, Violation{
				Rule:    string(RuleRequired),
				Keys:    []string{key},
				Message: formatMessage(RuleRequired, []string{key}, "%s is required", key),
			})
		}
	}
	for _, key := range def.Forbidden {
		for _, logical := range def.Documents {
			doc := docs[logical]
			if _, ok := doc.Values[key]; ok {
				violations = append(violations, Violation{
					Rule:    string(RuleForbidden),
					Keys:    []string{key},
					Message: formatMessage(RuleForbidden, []string{key}, "%s is forbidden in %s", key, logical),
				})
			}
		}
	}
	for _, rule := range def.Rules {
		violations = append(violations, evaluateRule(rule, def, docs, merged)...)
	}
	return violations
}

func evaluateRule(rule Rule, def Definition, docs map[string]schema.EnvSecretDocument, merged map[string]string) []Violation {
	switch rule.Kind {
	case RuleNonEmpty:
		value, ok := merged[rule.Key]
		if !ok {
			return []Violation{{
				Rule:    string(RuleNonEmpty),
				Keys:    []string{rule.Key},
				Message: formatMessage(RuleNonEmpty, []string{rule.Key}, "%s is missing", rule.Key),
			}}
		}
		if strings.TrimSpace(value) == "" {
			return []Violation{{
				Rule:    string(RuleNonEmpty),
				Keys:    []string{rule.Key},
				Message: formatMessage(RuleNonEmpty, []string{rule.Key}, "%s must be non-empty", rule.Key),
			}}
		}
	case RuleMinLength:
		value, ok := merged[rule.Key]
		if !ok {
			return []Violation{{
				Rule:    string(RuleMinLength),
				Keys:    []string{rule.Key},
				Message: formatMessage(RuleMinLength, []string{rule.Key}, "%s is missing", rule.Key),
			}}
		}
		if utf8.RuneCountInString(value) < rule.MinLength {
			return []Violation{{
				Rule:    string(RuleMinLength),
				Keys:    []string{rule.Key},
				Message: formatMessage(RuleMinLength, []string{rule.Key}, "%s does not meet min_length %d", rule.Key, rule.MinLength),
			}}
		}
	case RuleMatches:
		value, ok := merged[rule.Key]
		if !ok {
			return []Violation{{
				Rule:    string(RuleMatches),
				Keys:    []string{rule.Key},
				Message: formatMessage(RuleMatches, []string{rule.Key}, "%s is missing", rule.Key),
			}}
		}
		rx, err := regexp.Compile(rule.Matches)
		if err != nil {
			return []Violation{{
				Rule:    string(RuleMatches),
				Keys:    []string{rule.Key},
				Message: formatMessage(RuleMatches, []string{rule.Key}, "%s has an invalid matches pattern", rule.Key),
			}}
		}
		if !rx.MatchString(value) {
			return []Violation{{
				Rule:    string(RuleMatches),
				Keys:    []string{rule.Key},
				Message: formatMessage(RuleMatches, []string{rule.Key}, "%s does not match %q", rule.Key, rule.Matches),
			}}
		}
	case RuleEquals:
		return evaluateEquality(rule, true, docs, merged)
	case RuleNotEquals:
		return evaluateEquality(rule, false, docs, merged)
	case RuleDistinct:
		return evaluateDistinct(rule, merged)
	case RuleWhenRequire:
		value, ok := merged[rule.WhenKey]
		if !ok || value != rule.WhenEquals {
			return nil
		}
		var violations []Violation
		for _, key := range rule.Require {
			if _, present := merged[key]; !present {
				violations = append(violations, Violation{
					Rule:    string(RuleWhenRequire),
					Keys:    []string{key},
					Message: formatMessage(RuleWhenRequire, []string{key}, "%s is required when %s equals the configured value", key, rule.WhenKey),
				})
			}
		}
		return violations
	default:
		// An unrecognized rule must fail closed. Skipping it would let a
		// contract pass without enforcing that rule.
		return []Violation{{
			Rule:    string(RuleLoad),
			Keys:    []string{},
			Message: formatMessage(RuleLoad, nil, "unsupported contract rule"),
		}}
	}
	return nil
}

func evaluateEquality(rule Rule, wantEqual bool, docs map[string]schema.EnvSecretDocument, merged map[string]string) []Violation {
	kind := RuleEquals
	if !wantEqual {
		kind = RuleNotEquals
	}
	values := make([]string, 0, len(rule.Refs))
	keys := make([]string, 0, len(rule.Refs))
	for _, ref := range rule.Refs {
		keys = append(keys, refLabel(ref))
		value, ok := resolveRef(ref, docs, merged)
		if !ok {
			return []Violation{{
				Rule:    string(kind),
				Keys:    []string{refLabel(ref)},
				Message: formatMessage(kind, []string{refLabel(ref)}, "%s is missing", refLabel(ref)),
			}}
		}
		values = append(values, value)
	}
	if wantEqual {
		for i := 1; i < len(values); i++ {
			if values[i] != values[0] {
				return []Violation{{
					Rule:    string(RuleEquals),
					Keys:    keys,
					Message: formatMessage(RuleEquals, keys, "%s must be equal", strings.Join(keys, ", ")),
				}}
			}
		}
		return nil
	}
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[i] == values[j] {
				pair := []string{keys[i], keys[j]}
				return []Violation{{
					Rule:    string(RuleNotEquals),
					Keys:    pair,
					Message: formatMessage(RuleNotEquals, pair, "%s must not be equal", strings.Join(pair, ", ")),
				}}
			}
		}
	}
	return nil
}

func evaluateDistinct(rule Rule, merged map[string]string) []Violation {
	values := make([]string, 0, len(rule.Distinct))
	for _, key := range rule.Distinct {
		value, ok := merged[key]
		if !ok {
			return []Violation{{
				Rule:    string(RuleDistinct),
				Keys:    []string{key},
				Message: formatMessage(RuleDistinct, []string{key}, "%s is missing", key),
			}}
		}
		values = append(values, value)
	}
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[i] == values[j] {
				pair := []string{rule.Distinct[i], rule.Distinct[j]}
				return []Violation{{
					Rule:    string(RuleDistinct),
					Keys:    pair,
					Message: formatMessage(RuleDistinct, pair, "%s must be distinct", strings.Join(pair, ", ")),
				}}
			}
		}
	}
	return nil
}

func resolveRef(ref KeyRef, docs map[string]schema.EnvSecretDocument, merged map[string]string) (string, bool) {
	if ref.Document != "" {
		doc, ok := docs[ref.Document]
		if !ok {
			return "", false
		}
		value, ok := doc.Values[ref.Key]
		return value, ok
	}
	value, ok := merged[ref.Key]
	return value, ok
}

func refLabel(ref KeyRef) string {
	if ref.Document == "" {
		return ref.Key
	}
	return ref.Document + ":" + ref.Key
}

// formatMessage builds a secret-safe violation message.
//
// Only rule names, key names, thresholds, and regex patterns may be
// interpolated. Never pass secret values or actual lengths as format args.
func formatMessage(kind RuleKind, keys []string, format string, args ...any) string {
	_ = kind
	_ = keys
	return fmt.Sprintf(format, args...)
}
