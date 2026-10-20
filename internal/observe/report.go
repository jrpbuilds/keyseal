package observe

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/observe/internal/redact"
	"github.com/jrpbuilds/keyseal/internal/secretfile"
)

// side holds one document's file-level facts. It has no keys and no bytes.
type side struct {
	name       string
	source     string
	revision   string
	fileState  secretfile.State
	duplicates []string
	problem    string
	// decrypted is true once a values mapping was read. It separates "keys": []
	// (an encrypted document with no keys) from "keys": null (never read).
	decrypted bool
}

type sideWire struct {
	Name          string           `json:"name"`
	Source        string           `json:"source"`
	Revision      string           `json:"revision,omitempty"`
	FileState     secretfile.State `json:"file_state,omitempty"`
	DuplicateKeys []string         `json:"duplicate_keys,omitempty"`
	Problem       string           `json:"problem,omitempty"`
}

func (s side) wire() sideWire {
	return sideWire{
		Name:          s.name,
		Source:        s.source,
		Revision:      s.revision,
		FileState:     s.fileState,
		DuplicateKeys: s.duplicates,
		Problem:       s.problem,
	}
}

// header is the text form of a side's identity.
func (s side) header() string {
	var b strings.Builder
	fmt.Fprintf(&b, "name=%s source=%s", s.name, s.source)
	if s.revision != "" {
		fmt.Fprintf(&b, " revision=%s", s.revision)
	}
	if s.fileState != "" {
		fmt.Fprintf(&b, " file_state=%s", s.fileState)
	}
	return b.String()
}

// keysOrNull keeps an unread side as null and a read side as an array, even
// when it has no keys.
func keysOrNull[T any](items []T, read bool) []T {
	if !read {
		return nil
	}
	if items == nil {
		return []T{}
	}
	return items
}

// inspection is the value-free report for one document.
type inspection struct {
	side side
	keys []redact.Key
}

// Passed is true only when the document was read: a missing, placeholder, or
// plaintext file fails closed so CI cannot mistake it for an empty document.
func (ins inspection) Passed() bool { return ins.side.problem == "" }

func (ins inspection) Text() string {
	var b strings.Builder
	b.WriteString(ins.side.header() + "\n")
	for _, key := range ins.keys {
		b.WriteString(key.Line() + "\n")
	}
	for _, name := range ins.side.duplicates {
		fmt.Fprintf(&b, "duplicate_key=%s\n", name)
	}
	if ins.side.problem != "" {
		fmt.Fprintf(&b, "problem: %s\n", ins.side.problem)
	}
	fmt.Fprintf(&b, "passed=%t\n", ins.Passed())
	return b.String()
}

func (ins inspection) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		sideWire
		Keys   []redact.Key `json:"keys"`
		Passed bool         `json:"passed"`
	}{
		sideWire: ins.side.wire(),
		Keys:     keysOrNull(ins.keys, ins.side.decrypted),
		Passed:   ins.Passed(),
	})
}

// comparison is the value-free report for a left (baseline) and right
// (candidate) document.
type comparison struct {
	left, right side
	deltas      []redact.Delta
	assertion   Assertion
	// problems holds failures that belong to neither document alone.
	problems []string
}

func (c comparison) bothEncrypted() bool {
	return c.left.fileState == secretfile.StateEncrypted && c.right.fileState == secretfile.StateEncrypted
}

// Equal is true only when both documents are encrypted, were read cleanly, and
// every compared key is equal. A missing document is never equal, so a script
// reading only this field cannot treat two absent files as a match.
func (c comparison) Equal() bool {
	if !c.bothEncrypted() || !c.left.decrypted || !c.right.decrypted || len(c.problems) > 0 {
		return false
	}
	for _, delta := range c.deltas {
		if delta.Outcome() != redact.OutcomeEqual {
			return false
		}
	}
	return true
}

// Passed is the only exit rule. Any problem fails, and an assertion needs two
// encrypted documents so a missing side cannot satisfy it.
func (c comparison) Passed() bool {
	if c.left.problem != "" || c.right.problem != "" || len(c.problems) > 0 {
		return false
	}
	switch c.assertion {
	case AssertEqual:
		return c.Equal()
	case AssertUnequal:
		return c.bothEncrypted() && c.left.decrypted && c.right.decrypted && !c.Equal()
	}
	return true
}

func (c comparison) Text() string {
	var b strings.Builder
	b.WriteString("left " + c.left.header() + "\n")
	b.WriteString("right " + c.right.header() + "\n")
	for _, delta := range c.deltas {
		b.WriteString(delta.Line() + "\n")
	}
	for _, name := range c.left.duplicates {
		fmt.Fprintf(&b, "left_duplicate_key=%s\n", name)
	}
	for _, name := range c.right.duplicates {
		fmt.Fprintf(&b, "right_duplicate_key=%s\n", name)
	}
	for _, problem := range []string{c.left.problem, c.right.problem} {
		if problem != "" {
			fmt.Fprintf(&b, "problem: %s\n", problem)
		}
	}
	for _, problem := range c.problems {
		fmt.Fprintf(&b, "problem: %s\n", problem)
	}
	fmt.Fprintf(&b, "equal=%t\n", c.Equal())
	if c.assertion != AssertNone {
		fmt.Fprintf(&b, "assertion=%s\n", c.assertion)
	}
	fmt.Fprintf(&b, "passed=%t\n", c.Passed())
	return b.String()
}

func (c comparison) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Left      sideWire       `json:"left"`
		Right     sideWire       `json:"right"`
		Keys      []redact.Delta `json:"keys"`
		Equal     bool           `json:"equal"`
		Assertion Assertion      `json:"assertion,omitempty"`
		Problems  []string       `json:"problems,omitempty"`
		Passed    bool           `json:"passed"`
	}{
		Left:      c.left.wire(),
		Right:     c.right.wire(),
		Keys:      keysOrNull(c.deltas, c.left.decrypted && c.right.decrypted),
		Equal:     c.Equal(),
		Assertion: c.assertion,
		Problems:  c.problems,
		Passed:    c.Passed(),
	})
}
