package contract_test

import (
	"strings"
	"testing"

	"github.com/jrpbuilds/keyseal/internal/contract"
	"github.com/jrpbuilds/keyseal/internal/schema"
)

const secretMarker = "SUPER_SECRET_MARKER_VALUE_9f3a"

func docs(entries map[string]map[string]string) map[string]schema.EnvSecretDocument {
	out := make(map[string]schema.EnvSecretDocument, len(entries))
	for name, values := range entries {
		out[name] = schema.EnvSecretDocument{
			Version: 1,
			Kind:    "env",
			Name:    name,
			Values:  values,
		}
	}
	return out
}

func TestEvaluateRequiredForbiddenNonEmpty(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/app"},
		Required:  []string{"APP_KEY", "EMPTY_OK"},
		Forbidden: []string{"TWILIO_TOKEN"},
		Rules: []contract.Rule{
			{Kind: contract.RuleNonEmpty, Key: "APP_KEY", NonEmpty: true},
		},
	}
	got := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {
			"APP_KEY":      "   ",
			"EMPTY_OK":     "",
			"TWILIO_TOKEN": secretMarker,
		},
	}))
	if len(got) != 2 {
		t.Fatalf("expected 2 violations, got %#v", got)
	}
	// Source order: required/forbidden lists first, then rules.
	if got[0].Rule != "forbidden" || got[0].Keys[0] != "TWILIO_TOKEN" {
		t.Fatalf("unexpected first violation: %#v", got[0])
	}
	if got[1].Rule != "non_empty" || got[1].Keys[0] != "APP_KEY" {
		t.Fatalf("unexpected second violation: %#v", got[1])
	}
	assertNoSecretLeak(t, got)
}

func TestEvaluateForbiddenAcrossDocuments(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/shared", "production/app"},
		Forbidden: []string{"TWILIO_TOKEN"},
	}
	got := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/shared": {"TWILIO_TOKEN": secretMarker},
		"production/app":    {"APP_KEY": "ok"},
	}))
	if len(got) != 1 || got[0].Rule != "forbidden" {
		t.Fatalf("expected forbidden violation, got %#v", got)
	}
	if !strings.Contains(got[0].Message, "production/shared") {
		t.Fatalf("expected document name in message, got %#v", got[0])
	}
	assertNoSecretLeak(t, got)
}

func TestEvaluateMinLengthAndMatches(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/app"},
		Rules: []contract.Rule{
			{Kind: contract.RuleMinLength, Key: "PASS", MinLength: 4},
			{Kind: contract.RuleMatches, Key: "TOKEN", Matches: `^(sk|rk)_live_`},
			{Kind: contract.RuleMinLength, Key: "RUNE", MinLength: 2},
		},
	}
	got := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {
			"PASS":  "abc",
			"TOKEN": "pk_live_" + secretMarker,
			"RUNE":  "é",
		},
	}))
	if len(got) != 3 {
		t.Fatalf("expected 3 violations, got %#v", got)
	}
	if got[0].Message != "PASS does not meet min_length 4" {
		t.Fatalf("unexpected min_length message: %q", got[0].Message)
	}
	if !strings.Contains(got[1].Message, "does not match") || strings.Contains(got[1].Message, secretMarker) {
		t.Fatalf("unexpected matches message: %q", got[1].Message)
	}
	if got[2].Rule != "min_length" || got[2].Keys[0] != "RUNE" {
		t.Fatalf("expected rune length failure, got %#v", got[2])
	}
	assertNoSecretLeak(t, got)

	pass := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {
			"PASS":  "abcd",
			"TOKEN": "sk_live_ok",
			"RUNE":  "éé",
		},
	}))
	if len(pass) != 0 {
		t.Fatalf("expected pass, got %#v", pass)
	}
}

func TestEvaluateMissingKeyIsMissingNotLength(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/app"},
		Rules: []contract.Rule{
			{Kind: contract.RuleMinLength, Key: "PASS", MinLength: 8},
			{Kind: contract.RuleMatches, Key: "TOKEN", Matches: "^x"},
		},
	}
	got := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {},
	}))
	if len(got) != 2 {
		t.Fatalf("expected 2 violations, got %#v", got)
	}
	for _, v := range got {
		if !strings.Contains(v.Message, "is missing") {
			t.Fatalf("expected missing-key message, got %#v", v)
		}
		if strings.Contains(v.Message, "min_length") && strings.Contains(v.Message, "does not meet") {
			t.Fatalf("missing key must not report length failure: %#v", v)
		}
	}
}

func TestEvaluateEqualsAndNotEquals(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/app", "production/shared"},
		Rules: []contract.Rule{
			{
				Kind: contract.RuleEquals,
				Refs: []contract.KeyRef{
					{Document: "production/app", Key: "DB_PASSWORD"},
					{Document: "production/shared", Key: "DB_PASSWORD"},
				},
			},
			{
				Kind: contract.RuleNotEquals,
				Refs: []contract.KeyRef{
					{Key: "APP_KEY"},
					{Key: "SESSION_KEY"},
				},
			},
		},
	}
	fail := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {
			"DB_PASSWORD": "one",
			"APP_KEY":     secretMarker,
			"SESSION_KEY": secretMarker,
		},
		"production/shared": {
			"DB_PASSWORD": "two",
		},
	}))
	if len(fail) != 2 {
		t.Fatalf("expected 2 violations, got %#v", fail)
	}
	if fail[0].Rule != "equals" {
		t.Fatalf("expected equals first, got %#v", fail[0])
	}
	if fail[1].Rule != "not_equals" {
		t.Fatalf("expected not_equals second, got %#v", fail[1])
	}
	assertNoSecretLeak(t, fail)

	pass := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {
			"DB_PASSWORD": "same",
			"APP_KEY":     "a",
			"SESSION_KEY": "b",
		},
		"production/shared": {
			"DB_PASSWORD": "same",
		},
	}))
	if len(pass) != 0 {
		t.Fatalf("expected pass, got %#v", pass)
	}
}

func TestEvaluateDistinctAndWhen(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/app"},
		Rules: []contract.Rule{
			{Kind: contract.RuleDistinct, Distinct: []string{"APP_KEY", "SESSION_KEY"}},
			{
				Kind:       contract.RuleWhenRequire,
				WhenKey:    "FEATURE",
				WhenEquals: "true",
				Require:    []string{"FEATURE_SECRET"},
			},
		},
	}

	inactive := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {
			"APP_KEY":     "a",
			"SESSION_KEY": "b",
		},
	}))
	if len(inactive) != 0 {
		t.Fatalf("inactive when must not fail: %#v", inactive)
	}

	activeFail := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {
			"APP_KEY":     secretMarker,
			"SESSION_KEY": secretMarker,
			"FEATURE":     "true",
		},
	}))
	if len(activeFail) != 2 {
		t.Fatalf("expected distinct + when.require, got %#v", activeFail)
	}
	if activeFail[0].Rule != "distinct" || activeFail[1].Rule != "when.require" {
		t.Fatalf("unexpected order: %#v", activeFail)
	}
	assertNoSecretLeak(t, activeFail)
}

func TestEvaluateWhenDoesNotLeakConditionValue(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/app"},
		Rules: []contract.Rule{{
			Kind:       contract.RuleWhenRequire,
			WhenKey:    "FEATURE",
			WhenEquals: secretMarker,
			Require:    []string{"FEATURE_SECRET"},
		}},
	}
	inactive := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {"FEATURE": "false"},
	}))
	if len(inactive) != 0 {
		t.Fatalf("different condition value must not apply require: %#v", inactive)
	}
	active := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {"FEATURE": secretMarker},
	}))
	if len(active) != 1 || active[0].Rule != "when.require" {
		t.Fatalf("expected conditional requirement, got %#v", active)
	}
	assertNoSecretLeak(t, active)
}

func TestEvaluateNotEqualsMissingIsNotSuccess(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/app", "production/shared"},
		Rules: []contract.Rule{{
			Kind: contract.RuleNotEquals,
			Refs: []contract.KeyRef{
				{Document: "production/app", Key: "APP_KEY"},
				{Document: "production/shared", Key: "APP_KEY"},
			},
		}},
	}
	got := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app":    {"APP_KEY": secretMarker},
		"production/shared": {},
	}))
	if len(got) != 1 || !strings.Contains(got[0].Message, "is missing") {
		t.Fatalf("missing cross-document ref must fail closed, got %#v", got)
	}
	assertNoSecretLeak(t, got)

	equal := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app":    {"APP_KEY": secretMarker},
		"production/shared": {"APP_KEY": secretMarker},
	}))
	if len(equal) != 1 || equal[0].Rule != "not_equals" {
		t.Fatalf("equal cross-document values must fail not_equals, got %#v", equal)
	}
	assertNoSecretLeak(t, equal)
}

func TestEvaluateMinLengthDoesNotReportActualLength(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/app"},
		Rules: []contract.Rule{{
			Kind:      contract.RuleMinLength,
			Key:       "PASS",
			MinLength: 32,
		}},
	}
	got := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {"PASS": "short"},
	}))
	if len(got) != 1 {
		t.Fatalf("expected one violation, got %#v", got)
	}
	if strings.Contains(got[0].Message, "5") || strings.Contains(got[0].Message, "short") {
		t.Fatalf("min_length message leaked actual length or value: %q", got[0].Message)
	}
	if got[0].Message != "PASS does not meet min_length 32" {
		t.Fatalf("unexpected message: %q", got[0].Message)
	}
}

func TestEvaluateUnsupportedRuleFailsClosed(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/app"},
		Rules:     []contract.Rule{{Kind: "nope", Key: "APP_KEY"}},
	}
	got := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {"APP_KEY": secretMarker},
	}))
	if len(got) != 1 || got[0].Rule != "load" {
		t.Fatalf("unsupported rule must fail closed, got %#v", got)
	}
	assertNoSecretLeak(t, got)
}

func TestEvaluateUnavailableDocument(t *testing.T) {
	def := contract.Definition{
		Name:      "app",
		Documents: []string{"production/app", "production/missing"},
		Required:  []string{"APP_KEY"},
	}
	got := contract.Evaluate(def, docs(map[string]map[string]string{
		"production/app": {"APP_KEY": "x"},
	}))
	if len(got) != 1 || got[0].Rule != "load" {
		t.Fatalf("expected single load violation, got %#v", got)
	}
}

func assertNoSecretLeak(t *testing.T, violations []contract.Violation) {
	t.Helper()
	for _, v := range violations {
		if strings.Contains(v.Message, secretMarker) {
			t.Fatalf("violation message leaked secret value: %#v", v)
		}
		for _, key := range v.Keys {
			if strings.Contains(key, secretMarker) {
				t.Fatalf("violation keys leaked secret value: %#v", v)
			}
		}
	}
}
