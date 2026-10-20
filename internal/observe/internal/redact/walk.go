package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/jrpbuilds/keyseal/internal/schema"
	"gopkg.in/yaml.v3"
)

// fingerprintDomain separates these MACs from any other use of the same key.
const fingerprintDomain = "keyseal-fingerprint-v1\x00"

// ErrInvalidDocument means the YAML is not a version 1 env document with a
// values mapping. It never wraps a YAML error, which could quote content.
var ErrInvalidDocument = errors.New("not a valid env document")

// InvalidSideError attributes ErrInvalidDocument to one side of a comparison.
type InvalidSideError struct{ Right bool }

func (e InvalidSideError) Error() string { return ErrInvalidDocument.Error() }
func (e InvalidSideError) Unwrap() error { return ErrInvalidDocument }

// Options selects keys and optional metadata. It holds no secret material.
type Options struct {
	// Keys restricts the report to these names. Empty selects every key.
	Keys       []string
	ShowLength bool
	ShowType   bool
}

// Projection is the value-free view of one document.
type Projection struct {
	Keys       []Key
	Duplicates []string
}

// Comparison is the value-free result of comparing two documents.
type Comparison struct {
	Deltas          []Delta
	LeftDuplicates  []string
	RightDuplicates []string
	// MissingFromBoth lists requested keys that exist on neither side.
	MissingFromBoth []string
}

// Source is one input to CompareYAML. Absent marks a missing file, which
// compares as a document with no keys.
type Source struct {
	Plaintext []byte
	Absent    bool
}

type entry struct {
	state KeyState
	value string
	typ   ValueType
}

type document struct {
	entries    map[string]entry
	duplicates []string
}

var tagTypes = map[string]ValueType{
	"!!str":       TypeStr,
	"!!int":       TypeInt,
	"!!bool":      TypeBool,
	"!!float":     TypeFloat,
	"!!null":      TypeNull,
	"!!binary":    TypeBinary,
	"!!timestamp": TypeTimestamp,
}

// Project walks decrypted YAML and reports each selected key's state.
//
// plaintext is borrowed and not retained. A non-nil mac requests fingerprints
// for present scalars.
func Project(plaintext []byte, opt Options, mac []byte) (Projection, error) {
	doc, err := walk(plaintext)
	if err != nil {
		return Projection{}, err
	}
	names := selectNames(opt.Keys, doc.entries)
	keys := make([]Key, 0, len(names))
	for _, name := range names {
		e, ok := doc.entries[name]
		if !ok {
			e = entry{state: KeyMissing}
		}
		key, err := NewKey(name, e.state, annotate(e, opt, mac))
		if err != nil {
			return Projection{}, err
		}
		keys = append(keys, key)
	}
	return Projection{Keys: keys, Duplicates: filterNames(doc.duplicates, opt.Keys)}, nil
}

// CompareYAML compares left (the baseline) with right (the candidate).
// Equality is Go string equality on the stored scalar text, so type metadata
// and fingerprints never change an outcome. A non-scalar is never equal.
func CompareYAML(left, right Source, opt Options, mac []byte) (Comparison, error) {
	leftDoc, err := walkSource(left)
	if err != nil {
		return Comparison{}, InvalidSideError{Right: false}
	}
	rightDoc, err := walkSource(right)
	if err != nil {
		return Comparison{}, InvalidSideError{Right: true}
	}

	union := make(map[string]entry, len(leftDoc.entries)+len(rightDoc.entries))
	for name := range leftDoc.entries {
		union[name] = entry{}
	}
	for name := range rightDoc.entries {
		union[name] = entry{}
	}

	result := Comparison{
		LeftDuplicates:  filterNames(leftDoc.duplicates, opt.Keys),
		RightDuplicates: filterNames(rightDoc.duplicates, opt.Keys),
		Deltas:          []Delta{},
	}
	for _, name := range selectNames(opt.Keys, union) {
		l, inLeft := leftDoc.entries[name]
		r, inRight := rightDoc.entries[name]
		if !inLeft {
			l = entry{state: KeyMissing}
		}
		if !inRight {
			r = entry{state: KeyMissing}
		}
		if !inLeft && !inRight {
			result.MissingFromBoth = append(result.MissingFromBoth, name)
			continue
		}
		delta, err := NewDelta(name, outcomeOf(l, r), l.state, r.state, annotate(l, opt, mac), annotate(r, opt, mac))
		if err != nil {
			return Comparison{}, err
		}
		result.Deltas = append(result.Deltas, delta)
	}
	return result, nil
}

func outcomeOf(l, r entry) Outcome {
	switch {
	case l.state == KeyMissing:
		return OutcomeAdded
	case r.state == KeyMissing:
		return OutcomeRemoved
	case l.state.isScalar() && r.state.isScalar() && l.value == r.value:
		return OutcomeEqual
	default:
		return OutcomeDifferent
	}
}

func walkSource(src Source) (document, error) {
	if src.Absent {
		return document{entries: map[string]entry{}}, nil
	}
	return walk(src.Plaintext)
}

// walk parses the document once. Later duplicate keys win, as in
// schema.ParseYAMLDocument, and every duplicated name is recorded.
func walk(plaintext []byte) (document, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(plaintext, &node); err != nil {
		return document{}, ErrInvalidDocument
	}
	root := &node
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return document{}, ErrInvalidDocument
	}

	var values *yaml.Node
	var version, kind string
	for i := 0; i+1 < len(root.Content); i += 2 {
		field, val := root.Content[i], root.Content[i+1]
		switch field.Value {
		case "version":
			version = scalarText(val)
		case "kind":
			kind = scalarText(val)
		case "values":
			values = val
		}
	}
	if version != strconv.Itoa(schema.SupportedVersion) || kind != "env" || values == nil || values.Kind != yaml.MappingNode {
		return document{}, ErrInvalidDocument
	}

	doc := document{entries: map[string]entry{}}
	seen := map[string]int{}
	for i := 0; i+1 < len(values.Content); i += 2 {
		keyNode, valNode := values.Content[i], values.Content[i+1]
		if keyNode.Kind != yaml.ScalarNode {
			return document{}, ErrInvalidDocument
		}
		seen[keyNode.Value]++
		doc.entries[keyNode.Value] = entryOf(valNode)
	}
	for name, count := range seen {
		if count > 1 {
			doc.duplicates = append(doc.duplicates, name)
		}
	}
	sort.Strings(doc.duplicates)
	return doc, nil
}

func scalarText(n *yaml.Node) string {
	if n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func entryOf(n *yaml.Node) entry {
	if n.Kind != yaml.ScalarNode {
		return entry{state: KeyNonScalar, typ: TypeNonScalar}
	}
	typ, ok := tagTypes[n.ShortTag()]
	if !ok {
		typ = TypeUnknown
	}
	state := KeyPresent
	if n.Value == "" {
		state = KeyEmpty
	}
	return entry{state: state, value: n.Value, typ: typ}
}

func annotate(e entry, opt Options, mac []byte) Annotation {
	var ann Annotation
	switch {
	case e.state == KeyMissing:
		return ann
	case e.state == KeyNonScalar:
		if opt.ShowType {
			ann.Type = TypeNonScalar
		}
		return ann
	}
	if opt.ShowLength {
		length := utf8.RuneCountInString(e.value)
		ann.Length = &length
	}
	if opt.ShowType {
		ann.Type = e.typ
	}
	if mac != nil && e.state == KeyPresent {
		ann.Fingerprint = fingerprint(mac, e.value)
	}
	return ann
}

// fingerprint is a domain-separated HMAC-SHA256 of the stored scalar text.
// There is no unkeyed or truncated form.
func fingerprint(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fingerprintDomain))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// selectNames returns the requested names, de-duplicated and sorted, or every
// name in entries when nothing was requested.
func selectNames(requested []string, entries map[string]entry) []string {
	var names []string
	if len(requested) > 0 {
		names = slices.Clone(requested)
	} else {
		for name := range entries {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return slices.Compact(names)
}

func filterNames(names, requested []string) []string {
	if len(requested) == 0 {
		return names
	}
	var out []string
	for _, name := range names {
		if slices.Contains(requested, name) {
			out = append(out, name)
		}
	}
	return out
}
