// Package mutate applies non-interactive changes to encrypted env documents.
//
// Every change runs as one transaction: decrypt in memory, edit, re-encrypt
// through SOPS for the destination path, verify the ciphertext, then
// atomically replace the file. Plaintext never touches disk.
package mutate

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action describes what happened to one key in a document.
type Action string

const (
	Added     Action = "added"
	Updated   Action = "updated"
	Unchanged Action = "unchanged"
	Removed   Action = "removed"
)

// Change records the action applied to one key. It never carries values.
type Change struct {
	Key    string
	Action Action
}

// Document is a decrypted env document kept as a YAML node tree so comments,
// key order, and unrelated fields survive a mutation.
type Document struct {
	root   *yaml.Node
	values *yaml.Node
}

// ParseDocument parses decrypted YAML and locates the values mapping.
//
// Documents with duplicate top-level or value keys are rejected because it is
// ambiguous which entry a mutation should change.
func ParseDocument(plaintext []byte) (*Document, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(plaintext, &node); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parse yaml: expected a mapping document")
	}
	root := node.Content[0]
	if dupes := duplicateKeys(root); len(dupes) > 0 {
		return nil, fmt.Errorf("document has duplicate top-level keys: %s", strings.Join(dupes, ", "))
	}
	var values *yaml.Node
	for i := 0; i < len(root.Content)-1; i += 2 {
		if root.Content[i].Value == "values" {
			values = root.Content[i+1]
		}
	}
	if values == nil || values.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("document values must be a mapping")
	}

	for i := 0; i < len(values.Content)-1; i += 2 {
		if values.Content[i+1].Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("value for %s must be a string", values.Content[i].Value)
		}
	}
	if dupes := duplicateKeys(values); len(dupes) > 0 {
		return nil, fmt.Errorf("document has duplicate keys: %s", strings.Join(dupes, ", "))
	}
	return &Document{root: &node, values: values}, nil
}

// duplicateKeys returns the sorted keys that appear more than once in mapping.
func duplicateKeys(mapping *yaml.Node) []string {
	seen := map[string]bool{}
	var dupes []string
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		key := mapping.Content[i].Value
		if seen[key] {
			dupes = append(dupes, key)
		}
		seen[key] = true
	}
	sort.Strings(dupes)
	return dupes
}

// unencryptedValueKeys returns the keys whose values in SOPS output are not
// encrypted, which happens when a creation rule narrows encryption with
// options such as encrypted_regex. It never returns value content.
func unencryptedValueKeys(ciphertext []byte) ([]string, error) {
	doc, err := ParseDocument(ciphertext)
	if err != nil {
		return nil, err
	}
	var keys []string
	for i := 0; i < len(doc.values.Content)-1; i += 2 {
		if !strings.HasPrefix(doc.values.Content[i+1].Value, "ENC[") {
			keys = append(keys, doc.values.Content[i].Value)
		}
	}
	return keys, nil
}

// Values returns a copy of the document's key/value pairs.
func (d *Document) Values() map[string]string {
	out := make(map[string]string, len(d.values.Content)/2)
	for i := 0; i < len(d.values.Content)-1; i += 2 {
		out[d.values.Content[i].Value] = d.values.Content[i+1].Value
	}
	return out
}

// Set adds or replaces a value. New keys are appended to keep existing order.
func (d *Document) Set(key, value string) Action {
	for i := 0; i < len(d.values.Content)-1; i += 2 {
		if d.values.Content[i].Value != key {
			continue
		}
		valueNode := d.values.Content[i+1]
		if valueNode.Value == value {
			return Unchanged
		}
		setStringScalar(valueNode, value)
		return Updated
	}
	d.values.Content = append(d.values.Content, stringScalar(key), stringScalar(value))
	return Added
}

// Unset removes a key and reports whether it was present.
func (d *Document) Unset(key string) bool {
	for i := 0; i < len(d.values.Content)-1; i += 2 {
		if d.values.Content[i].Value == key {
			d.values.Content = append(d.values.Content[:i], d.values.Content[i+2:]...)
			return true
		}
	}
	return false
}

// SetName replaces the top-level document name, adding it when missing.
func (d *Document) SetName(name string) {
	mapping := d.root.Content[0]
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		if mapping.Content[i].Value == "name" {
			setStringScalar(mapping.Content[i+1], name)
			return
		}
	}
	mapping.Content = append(mapping.Content, stringScalar("name"), stringScalar(name))
}

// Marshal encodes the document with the same indentation as starter documents.
func (d *Document) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(d.root); err != nil {
		return nil, fmt.Errorf("marshal document: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("marshal document: %w", err)
	}
	return buf.Bytes(), nil
}

// stringScalar builds a node explicitly tagged as a string so values such as
// "true" or "0123" are quoted instead of changing type.
func stringScalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

// setStringScalar replaces a scalar's content while keeping its comments.
func setStringScalar(node *yaml.Node, value string) {
	node.Kind = yaml.ScalarNode
	node.Tag = "!!str"
	node.Style = 0
	node.Value = value
}
