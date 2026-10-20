// Package redact turns decrypted env documents into value-free key facts.
package redact

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// KeyState is a key's presence in one document's values mapping.
type KeyState string

const (
	// KeyPresent means the stored text is non-empty. Whitespace counts as present.
	KeyPresent KeyState = "present"
	// KeyEmpty means the stored text is exactly "".
	KeyEmpty KeyState = "empty"
	// KeyMissing means the key is absent from the values mapping.
	KeyMissing KeyState = "missing"
	// KeyNonScalar means the value is a mapping, sequence, or alias. It is never
	// treated as empty, because a YAML collection has no scalar text.
	KeyNonScalar KeyState = "non_scalar"
)

func (s KeyState) valid() bool {
	switch s {
	case KeyPresent, KeyEmpty, KeyMissing, KeyNonScalar:
		return true
	}
	return false
}

func (s KeyState) isScalar() bool {
	return s == KeyPresent || s == KeyEmpty
}

// ValueType is the YAML type classification a scalar carried before Keyseal
// reduced it to text.
type ValueType string

const (
	TypeStr       ValueType = "str"
	TypeInt       ValueType = "int"
	TypeBool      ValueType = "bool"
	TypeFloat     ValueType = "float"
	TypeNull      ValueType = "null"
	TypeBinary    ValueType = "binary"
	TypeTimestamp ValueType = "timestamp"
	TypeNonScalar ValueType = "non_scalar"
	TypeUnknown   ValueType = "unknown"
)

func (t ValueType) valid() bool {
	switch t {
	case "", TypeStr, TypeInt, TypeBool, TypeFloat, TypeNull, TypeBinary, TypeTimestamp, TypeNonScalar, TypeUnknown:
		return true
	}
	return false
}

// Outcome is how one key differs between a left (baseline) and right
// (candidate) document. The words differ from mutate.Action on purpose: that
// type records a write, this one reports a read.
type Outcome string

const (
	OutcomeEqual     Outcome = "equal"
	OutcomeDifferent Outcome = "different"
	OutcomeAdded     Outcome = "added"
	OutcomeRemoved   Outcome = "removed"
)

func (o Outcome) valid() bool {
	switch o {
	case OutcomeEqual, OutcomeDifferent, OutcomeAdded, OutcomeRemoved:
		return true
	}
	return false
}

// Annotation is optional display metadata. It never changes an outcome.
type Annotation struct {
	// Length is a rune count, set only for scalars when requested.
	Length *int
	Type   ValueType
	// Fingerprint is a lowercase hex keyed MAC, set only for present scalars
	// when requested.
	Fingerprint string
}

// validateFor rejects metadata that would disclose or invent facts for a state.
func (a Annotation) validateFor(name string, state KeyState) error {
	if !a.Type.valid() {
		return fmt.Errorf("key %q: unknown value type", name)
	}
	switch state {
	case KeyMissing:
		if a.Length != nil || a.Fingerprint != "" || a.Type != "" {
			return fmt.Errorf("key %q: a missing key has no metadata", name)
		}
	case KeyNonScalar:
		if a.Length != nil || a.Fingerprint != "" {
			return fmt.Errorf("key %q: a non-scalar key has no length or fingerprint", name)
		}
		if a.Type != "" && a.Type != TypeNonScalar {
			return fmt.Errorf("key %q: a non-scalar key has a non-scalar type", name)
		}
	case KeyEmpty:
		if a.Fingerprint != "" {
			return fmt.Errorf("key %q: an empty key is never fingerprinted", name)
		}
	}
	return nil
}

// Key is one key's facts in one document. It has no value field.
type Key struct {
	name  string
	state KeyState
	ann   Annotation
}

// NewKey is the only constructor. It rejects an empty name, an unknown state,
// and metadata that does not fit the state. Errors carry the key name only.
func NewKey(name string, state KeyState, ann Annotation) (Key, error) {
	if name == "" {
		return Key{}, fmt.Errorf("key name is required")
	}
	if !state.valid() {
		return Key{}, fmt.Errorf("key %q: unknown state", name)
	}
	if err := ann.validateFor(name, state); err != nil {
		return Key{}, err
	}
	return Key{name: name, state: state, ann: ann}, nil
}

func (k Key) Name() string    { return k.name }
func (k Key) State() KeyState { return k.state }

// Line renders the key as one line of report text.
func (k Key) Line() string {
	var b strings.Builder
	b.WriteString(textName(k.name))
	b.WriteString(" state=" + string(k.state))
	writeAnnotation(&b, "", k.ann)
	return b.String()
}

type keyWire struct {
	Name        string    `json:"name"`
	State       KeyState  `json:"state"`
	Length      *int      `json:"length,omitempty"`
	Type        ValueType `json:"type,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

// MarshalJSON emits an allowlist, so a field added to Key later is not
// reported until this struct is edited too.
func (k Key) MarshalJSON() ([]byte, error) {
	return json.Marshal(keyWire{
		Name:        k.name,
		State:       k.state,
		Length:      k.ann.Length,
		Type:        k.ann.Type,
		Fingerprint: k.ann.Fingerprint,
	})
}

// Delta is one key's outcome between two documents.
type Delta struct {
	name       string
	outcome    Outcome
	leftState  KeyState
	rightState KeyState
	leftAnn    Annotation
	rightAnn   Annotation
}

// NewDelta rejects outcomes that contradict the key states they summarize.
func NewDelta(name string, outcome Outcome, leftState, rightState KeyState, leftAnn, rightAnn Annotation) (Delta, error) {
	if name == "" {
		return Delta{}, fmt.Errorf("key name is required")
	}
	if !outcome.valid() || !leftState.valid() || !rightState.valid() {
		return Delta{}, fmt.Errorf("key %q: unknown outcome or state", name)
	}
	leftMissing, rightMissing := leftState == KeyMissing, rightState == KeyMissing
	var consistent bool
	switch outcome {
	case OutcomeAdded:
		consistent = leftMissing && !rightMissing
	case OutcomeRemoved:
		consistent = rightMissing && !leftMissing
	case OutcomeEqual:
		consistent = !leftMissing && !rightMissing && leftState.isScalar() && rightState.isScalar()
	case OutcomeDifferent:
		consistent = !leftMissing && !rightMissing
	}
	if !consistent {
		return Delta{}, fmt.Errorf("key %q: outcome %s contradicts states %s and %s", name, outcome, leftState, rightState)
	}
	if err := leftAnn.validateFor(name, leftState); err != nil {
		return Delta{}, err
	}
	if err := rightAnn.validateFor(name, rightState); err != nil {
		return Delta{}, err
	}
	return Delta{name: name, outcome: outcome, leftState: leftState, rightState: rightState, leftAnn: leftAnn, rightAnn: rightAnn}, nil
}

func (d Delta) Name() string     { return d.name }
func (d Delta) Outcome() Outcome { return d.outcome }

// Line renders the delta as one line of report text.
func (d Delta) Line() string {
	var b strings.Builder
	b.WriteString(textName(d.name))
	fmt.Fprintf(&b, " outcome=%s left_state=%s right_state=%s", d.outcome, d.leftState, d.rightState)
	writeAnnotation(&b, "left_", d.leftAnn)
	writeAnnotation(&b, "right_", d.rightAnn)
	return b.String()
}

type deltaWire struct {
	Name             string    `json:"name"`
	Outcome          Outcome   `json:"outcome"`
	LeftState        KeyState  `json:"left_state"`
	RightState       KeyState  `json:"right_state"`
	LeftLength       *int      `json:"left_length,omitempty"`
	LeftType         ValueType `json:"left_type,omitempty"`
	LeftFingerprint  string    `json:"left_fingerprint,omitempty"`
	RightLength      *int      `json:"right_length,omitempty"`
	RightType        ValueType `json:"right_type,omitempty"`
	RightFingerprint string    `json:"right_fingerprint,omitempty"`
}

// MarshalJSON emits an allowlist, like Key.MarshalJSON.
func (d Delta) MarshalJSON() ([]byte, error) {
	return json.Marshal(deltaWire{
		Name:             d.name,
		Outcome:          d.outcome,
		LeftState:        d.leftState,
		RightState:       d.rightState,
		LeftLength:       d.leftAnn.Length,
		LeftType:         d.leftAnn.Type,
		LeftFingerprint:  d.leftAnn.Fingerprint,
		RightLength:      d.rightAnn.Length,
		RightType:        d.rightAnn.Type,
		RightFingerprint: d.rightAnn.Fingerprint,
	})
}

func writeAnnotation(b *strings.Builder, prefix string, ann Annotation) {
	if ann.Length != nil {
		fmt.Fprintf(b, " %slength=%d", prefix, *ann.Length)
	}
	if ann.Type != "" {
		fmt.Fprintf(b, " %stype=%s", prefix, ann.Type)
	}
	if ann.Fingerprint != "" {
		fmt.Fprintf(b, " %sfingerprint=%s", prefix, ann.Fingerprint)
	}
}

// textName quotes names that could forge extra fields or lines in text output.
// Key names come from decrypted content, so they are not trusted.
func textName(name string) string {
	needsQuote := strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsSpace(r) || !unicode.IsPrint(r) || r == '='
	})
	if needsQuote {
		return strconv.Quote(name)
	}
	return name
}
