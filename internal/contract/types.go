// Package contract defines declarative secret contracts and evaluates them
// against decrypted env documents without exposing secret values.
package contract

import "fmt"

// RuleKind identifies which contract rule produced a violation.
type RuleKind string

const (
	RuleRequired    RuleKind = "required"
	RuleForbidden   RuleKind = "forbidden"
	RuleNonEmpty    RuleKind = "non_empty"
	RuleMinLength   RuleKind = "min_length"
	RuleMatches     RuleKind = "matches"
	RuleEquals      RuleKind = "equals"
	RuleNotEquals   RuleKind = "not_equals"
	RuleDistinct    RuleKind = "distinct"
	RuleWhenRequire RuleKind = "when.require"
	RuleLoad        RuleKind = "load"
)

// KeyRef names a secret key, optionally scoped to one contract document.
type KeyRef struct {
	Document string
	Key      string
}

// Rule is one evaluated constraint inside a contract.
type Rule struct {
	Kind       RuleKind
	Key        string
	MinLength  int
	Matches    string
	NonEmpty   bool
	Refs       []KeyRef
	Distinct   []string
	WhenKey    string
	WhenEquals string
	Require    []string
}

// Definition is one named contract after decoding and from-file resolution.
type Definition struct {
	Name      string
	Documents []string
	Required  []string
	Forbidden []string
	Rules     []Rule
}

// Violation reports a failed rule without including secret values.
//
// Message formatting must only allowlist rule names, key names, thresholds,
// and regex patterns. Never interpolate secret values or actual lengths.
type Violation struct {
	Rule    string   `json:"rule"`
	Keys    []string `json:"keys"`
	Message string   `json:"message"`
}

// Problem is a definition or from-file load failure for one named contract.
type Problem struct {
	Name    string
	Message string
}

func (p Problem) Error() string {
	if p.Name == "" {
		return p.Message
	}
	return fmt.Sprintf("contracts.%s: %s", p.Name, p.Message)
}
