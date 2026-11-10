// Package render merges decrypted env documents and renders runtime formats.
package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/schema"
	"gopkg.in/yaml.v3"
)

// MergeEnvDocs merges env document values in argument order.
//
// Later documents override earlier ones so callers can layer shared and more
// specific secret files deterministically.
func MergeEnvDocs(docs []schema.EnvSecretDocument) map[string]string {
	merged := map[string]string{}
	for _, doc := range docs {
		// Last write wins by design: callers pass files in precedence order.
		for key, value := range doc.Values {
			merged[key] = value
		}
	}
	return merged
}

// Select returns a new map containing only the requested keys that are present
// in values. Missing names are returned in request order. Empty-string values
// count as present. The returned map is independent of values so callers can
// discard the full merge after filtering.
func Select(values map[string]string, keys []string) (map[string]string, []string) {
	selected := make(map[string]string, len(keys))
	missing := make([]string, 0)
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			missing = append(missing, key)
			continue
		}
		selected[key] = value
	}
	return selected, missing
}

// RenderDotenv renders env values in stable key order with conservative
// escaping so the output is predictable and shell-friendly.
func RenderDotenv(values map[string]string) ([]byte, error) {
	keys := sortedKeys(values)
	var buf bytes.Buffer
	for _, key := range keys {
		if _, err := fmt.Fprintf(&buf, "%s=\"%s\"\n", key, escapeDotenv(values[key])); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// RenderJSON renders env values as an indented JSON object.
func RenderJSON(values map[string]string) ([]byte, error) {
	return json.MarshalIndent(values, "", "  ")
}

// RenderYAML renders env values as a YAML mapping in stable key order.
func RenderYAML(values map[string]string) ([]byte, error) {
	node := &yaml.Node{Kind: yaml.MappingNode}
	for _, key := range sortedKeys(values) {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: values[key]},
		)
	}
	return yaml.Marshal(node)
}

// Render selects the requested output format.
func Render(format string, values map[string]string) ([]byte, error) {
	switch format {
	case "dotenv":
		return RenderDotenv(values)
	case "json":
		return RenderJSON(values)
	case "yaml":
		return RenderYAML(values)
	default:
		return nil, fmt.Errorf("unsupported render format %q", format)
	}
}

func escapeDotenv(value string) string {
	// Dotenv files are line-oriented, so newlines and quotes must be escaped to
	// avoid silently changing the shape of the rendered environment.
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"\n", "\\n",
		"\"", "\\\"",
	)
	return replacer.Replace(value)
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
