package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAML node helpers used by strict top-level decoders such as access_profiles.
// The contract package keeps its own copies so that package stays self-contained.

func rootMapping(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	return node
}

func mappingChild(node *yaml.Node, key string) (*yaml.Node, bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i < len(node.Content)-1; i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1], true
		}
	}
	return nil, false
}

func mappingKeys(node *yaml.Node) (map[string]*yaml.Node, error) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected a mapping")
	}
	out := make(map[string]*yaml.Node, len(node.Content)/2)
	for i := 0; i < len(node.Content)-1; i += 2 {
		key := node.Content[i].Value
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate field %q", key)
		}
		out[key] = node.Content[i+1]
	}
	return out, nil
}

func isNullNode(node *yaml.Node) bool {
	return node != nil && node.Tag == "!!null"
}

func optionalStringSequence(node *yaml.Node, field string) ([]string, error) {
	if node == nil || isNullNode(node) {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s must be a sequence", field)
	}
	out := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("%s entries must be strings", field)
		}
		value := strings.TrimSpace(item.Value)
		if value == "" {
			return nil, fmt.Errorf("%s entries must not be empty", field)
		}
		out = append(out, value)
	}
	return out, nil
}
