package contract

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/repo"
	"gopkg.in/yaml.v3"
)

var contractNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// LoadResult holds successfully decoded contracts and per-name problems.
type LoadResult struct {
	Contracts map[string]Definition
	Problems  []Problem
}

// LoadFromConfigYAML extracts and strictly decodes the top-level contracts map
// from a keyseal.yaml document. Paths in from: are resolved relative to
// configDir. keyPattern validates every env key name that appears in contracts.
func LoadFromConfigYAML(data []byte, configDir, keyPattern string) (LoadResult, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return LoadResult{}, fmt.Errorf("parse config yaml: %w", err)
	}
	mapping := rootMapping(&root)
	if mapping == nil {
		return LoadResult{Contracts: map[string]Definition{}}, nil
	}

	contractsNode, ok := mappingChild(mapping, "contracts")
	if !ok || contractsNode == nil || isNullNode(contractsNode) {
		return LoadResult{Contracts: map[string]Definition{}}, nil
	}
	if contractsNode.Kind != yaml.MappingNode {
		return LoadResult{}, fmt.Errorf("contracts must be a mapping")
	}

	keyRX, err := regexp.Compile(keyPattern)
	if err != nil {
		return LoadResult{}, fmt.Errorf("validation.key_pattern: %w", err)
	}

	out := LoadResult{Contracts: map[string]Definition{}}
	seenNames := map[string]struct{}{}
	for i := 0; i < len(contractsNode.Content)-1; i += 2 {
		nameNode := contractsNode.Content[i]
		bodyNode := contractsNode.Content[i+1]
		name := nameNode.Value
		if _, dup := seenNames[name]; dup {
			out.Problems = append(out.Problems, Problem{Name: name, Message: "duplicate contract name"})
			continue
		}
		seenNames[name] = struct{}{}
		if !contractNamePattern.MatchString(name) {
			out.Problems = append(out.Problems, Problem{
				Name:    name,
				Message: fmt.Sprintf("invalid contract name %q (must match %s)", name, contractNamePattern.String()),
			})
			continue
		}
		def, err := decodeContractBody(name, bodyNode, configDir, keyRX, false)
		if err != nil {
			out.Problems = append(out.Problems, Problem{Name: name, Message: err.Error()})
			continue
		}
		out.Contracts[name] = def
	}
	return out, nil
}

func decodeContractBody(name string, node *yaml.Node, configDir string, keyRX *regexp.Regexp, fromFile bool) (Definition, error) {
	if node == nil || isNullNode(node) {
		return Definition{}, fmt.Errorf("contract body is required")
	}
	if node.Kind != yaml.MappingNode {
		return Definition{}, fmt.Errorf("contract body must be a mapping")
	}

	keys, err := mappingKeys(node)
	if err != nil {
		return Definition{}, err
	}

	fromPath, hasFrom := keys["from"]
	if hasFrom {
		if fromFile {
			return Definition{}, fmt.Errorf("from files must not contain a nested from field")
		}
		disallowed := []string{"documents", "required", "forbidden", "rules"}
		for _, key := range disallowed {
			if _, ok := keys[key]; ok {
				return Definition{}, fmt.Errorf("from cannot be combined with inline %s", key)
			}
		}
		for key := range keys {
			if key != "from" {
				return Definition{}, fmt.Errorf("unknown field %q", key)
			}
		}
		path, err := scalarText(fromPath)
		if err != nil {
			return Definition{}, fmt.Errorf("from: %w", err)
		}
		body, err := readFromFile(configDir, path)
		if err != nil {
			return Definition{}, err
		}
		var fileRoot yaml.Node
		if err := yaml.Unmarshal(body, &fileRoot); err != nil {
			return Definition{}, fmt.Errorf("parse from file %q: %w", path, err)
		}
		fileMapping := rootMapping(&fileRoot)
		if fileMapping == nil {
			return Definition{}, fmt.Errorf("from file %q must be a mapping", path)
		}
		return decodeContractBody(name, fileMapping, configDir, keyRX, true)
	}

	allowed := map[string]struct{}{
		"documents": {},
		"required":  {},
		"forbidden": {},
		"rules":     {},
	}
	for key := range keys {
		if _, ok := allowed[key]; !ok {
			return Definition{}, fmt.Errorf("unknown field %q", key)
		}
	}

	def := Definition{Name: name}
	if docsNode, ok := keys["documents"]; ok {
		docs, err := stringSequence(docsNode, "documents")
		if err != nil {
			return Definition{}, err
		}
		if len(docs) == 0 {
			return Definition{}, fmt.Errorf("documents must list at least one logical name")
		}
		seen := map[string]struct{}{}
		for _, doc := range docs {
			if err := repo.ValidateLogicalName(doc); err != nil {
				return Definition{}, fmt.Errorf("documents: %w", err)
			}
			if _, dup := seen[doc]; dup {
				return Definition{}, fmt.Errorf("documents: duplicate logical name %q", doc)
			}
			seen[doc] = struct{}{}
		}
		def.Documents = docs
	} else {
		return Definition{}, fmt.Errorf("documents is required")
	}

	if reqNode, ok := keys["required"]; ok {
		required, err := stringSequence(reqNode, "required")
		if err != nil {
			return Definition{}, err
		}
		if err := validateKeyNames(required, keyRX, "required"); err != nil {
			return Definition{}, err
		}
		def.Required = required
	}
	if forbNode, ok := keys["forbidden"]; ok {
		forbidden, err := stringSequence(forbNode, "forbidden")
		if err != nil {
			return Definition{}, err
		}
		if err := validateKeyNames(forbidden, keyRX, "forbidden"); err != nil {
			return Definition{}, err
		}
		def.Forbidden = forbidden
	}
	if rulesNode, ok := keys["rules"]; ok {
		rules, err := decodeRules(rulesNode, def.Documents, keyRX)
		if err != nil {
			return Definition{}, err
		}
		def.Rules = rules
	}

	if err := validateDefinitionShape(def); err != nil {
		return Definition{}, err
	}
	return def, nil
}

func decodeRules(node *yaml.Node, documents []string, keyRX *regexp.Regexp) ([]Rule, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("rules must be a sequence")
	}
	rules := make([]Rule, 0, len(node.Content))
	for idx, item := range node.Content {
		rule, err := decodeRule(item, documents, keyRX)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", idx, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func decodeRule(node *yaml.Node, documentNames []string, keyRX *regexp.Regexp) (Rule, error) {
	documents := make(map[string]struct{}, len(documentNames))
	for _, name := range documentNames {
		documents[name] = struct{}{}
	}
	if node.Kind != yaml.MappingNode {
		return Rule{}, fmt.Errorf("rule must be a mapping")
	}
	keys, err := mappingKeys(node)
	if err != nil {
		return Rule{}, err
	}

	operators := []string{"key", "equals", "not_equals", "distinct", "when"}
	found := make([]string, 0, 1)
	for _, op := range operators {
		if _, ok := keys[op]; ok {
			found = append(found, op)
		}
	}
	if len(found) == 0 {
		return Rule{}, fmt.Errorf("rule must set one of key, equals, not_equals, distinct, or when")
	}
	if len(found) > 1 {
		return Rule{}, fmt.Errorf("rule mixes incompatible operators %s", strings.Join(found, ", "))
	}

	switch found[0] {
	case "key":
		return decodeKeyRule(keys, keyRX)
	case "equals":
		refs, err := decodeKeyRefs(keys["equals"], "equals", documents, keyRX)
		if err != nil {
			return Rule{}, err
		}
		if len(refs) < 2 {
			return Rule{}, fmt.Errorf("equals must list at least two key refs")
		}
		if err := rejectDuplicateRefs(refs, "equals", documentNames); err != nil {
			return Rule{}, err
		}
		if len(keys) != 1 {
			return Rule{}, fmt.Errorf("equals rule must not set other fields")
		}
		return Rule{Kind: RuleEquals, Refs: refs}, nil
	case "not_equals":
		refs, err := decodeKeyRefs(keys["not_equals"], "not_equals", documents, keyRX)
		if err != nil {
			return Rule{}, err
		}
		if len(refs) < 2 {
			return Rule{}, fmt.Errorf("not_equals must list at least two key refs")
		}
		if err := rejectDuplicateRefs(refs, "not_equals", documentNames); err != nil {
			return Rule{}, err
		}
		if len(keys) != 1 {
			return Rule{}, fmt.Errorf("not_equals rule must not set other fields")
		}
		return Rule{Kind: RuleNotEquals, Refs: refs}, nil
	case "distinct":
		names, err := stringSequence(keys["distinct"], "distinct")
		if err != nil {
			return Rule{}, err
		}
		if len(names) < 2 {
			return Rule{}, fmt.Errorf("distinct must list at least two keys")
		}
		if err := validateKeyNames(names, keyRX, "distinct"); err != nil {
			return Rule{}, err
		}
		if len(keys) != 1 {
			return Rule{}, fmt.Errorf("distinct rule must not set other fields")
		}
		return Rule{Kind: RuleDistinct, Distinct: names}, nil
	case "when":
		return decodeWhenRule(keys, keyRX)
	default:
		return Rule{}, fmt.Errorf("unsupported rule operator %q", found[0])
	}
}

func decodeKeyRule(keys map[string]*yaml.Node, keyRX *regexp.Regexp) (Rule, error) {
	key, err := scalarText(keys["key"])
	if err != nil {
		return Rule{}, fmt.Errorf("key: %w", err)
	}
	if !keyRX.MatchString(key) {
		return Rule{}, fmt.Errorf("key %q does not match validation.key_pattern", key)
	}

	var (
		hasMin      bool
		hasMatches  bool
		hasNonEmpty bool
		rule        = Rule{Key: key}
	)
	for field := range keys {
		switch field {
		case "key":
		case "min_length":
			hasMin = true
		case "matches":
			hasMatches = true
		case "non_empty":
			hasNonEmpty = true
		default:
			return Rule{}, fmt.Errorf("unknown field %q on key rule", field)
		}
	}
	ops := 0
	if hasMin {
		ops++
	}
	if hasMatches {
		ops++
	}
	if hasNonEmpty {
		ops++
	}
	if ops != 1 {
		return Rule{}, fmt.Errorf("key rule must set exactly one of min_length, matches, or non_empty")
	}

	switch {
	case hasMin:
		n, err := intScalar(keys["min_length"])
		if err != nil {
			return Rule{}, fmt.Errorf("min_length: %w", err)
		}
		if n < 1 {
			return Rule{}, fmt.Errorf("min_length must be >= 1")
		}
		rule.Kind = RuleMinLength
		rule.MinLength = n
	case hasMatches:
		pattern, err := scalarText(keys["matches"])
		if err != nil {
			return Rule{}, fmt.Errorf("matches: %w", err)
		}
		if pattern == "" {
			return Rule{}, fmt.Errorf("matches must not be empty")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return Rule{}, fmt.Errorf("matches: invalid regex: %w", err)
		}
		rule.Kind = RuleMatches
		rule.Matches = pattern
	case hasNonEmpty:
		flag, err := boolScalarTrue(keys["non_empty"])
		if err != nil {
			return Rule{}, fmt.Errorf("non_empty: %w", err)
		}
		if !flag {
			return Rule{}, fmt.Errorf("non_empty must be true")
		}
		rule.Kind = RuleNonEmpty
		rule.NonEmpty = true
	}
	return rule, nil
}

func decodeWhenRule(keys map[string]*yaml.Node, keyRX *regexp.Regexp) (Rule, error) {
	whenNode := keys["when"]
	if whenNode.Kind != yaml.MappingNode {
		return Rule{}, fmt.Errorf("when must be a mapping")
	}
	whenKeys, err := mappingKeys(whenNode)
	if err != nil {
		return Rule{}, err
	}
	for field := range whenKeys {
		switch field {
		case "key", "equals":
		default:
			return Rule{}, fmt.Errorf("when: unknown field %q", field)
		}
	}
	whenKeyNode, ok := whenKeys["key"]
	if !ok {
		return Rule{}, fmt.Errorf("when.key is required")
	}
	whenKey, err := scalarText(whenKeyNode)
	if err != nil {
		return Rule{}, fmt.Errorf("when.key: %w", err)
	}
	if !keyRX.MatchString(whenKey) {
		return Rule{}, fmt.Errorf("when.key %q does not match validation.key_pattern", whenKey)
	}
	equalsNode, ok := whenKeys["equals"]
	if !ok {
		return Rule{}, fmt.Errorf("when.equals is required")
	}
	whenEquals, err := scalarText(equalsNode)
	if err != nil {
		return Rule{}, fmt.Errorf("when.equals: %w", err)
	}

	requireNode, ok := keys["require"]
	if !ok {
		return Rule{}, fmt.Errorf("when rule requires require")
	}
	require, err := stringSequence(requireNode, "require")
	if err != nil {
		return Rule{}, err
	}
	if len(require) == 0 {
		return Rule{}, fmt.Errorf("require must list at least one key")
	}
	if err := validateKeyNames(require, keyRX, "require"); err != nil {
		return Rule{}, err
	}
	for field := range keys {
		switch field {
		case "when", "require":
		default:
			return Rule{}, fmt.Errorf("when rule must not set field %q", field)
		}
	}
	return Rule{
		Kind:       RuleWhenRequire,
		WhenKey:    whenKey,
		WhenEquals: whenEquals,
		Require:    require,
	}, nil
}

func decodeKeyRefs(node *yaml.Node, field string, documents map[string]struct{}, keyRX *regexp.Regexp) ([]KeyRef, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s must be a sequence", field)
	}
	refs := make([]KeyRef, 0, len(node.Content))
	for idx, item := range node.Content {
		ref, err := decodeKeyRef(item, documents, keyRX)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, idx, err)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func decodeKeyRef(node *yaml.Node, documents map[string]struct{}, keyRX *regexp.Regexp) (KeyRef, error) {
	if node.Kind != yaml.MappingNode {
		return KeyRef{}, fmt.Errorf("key ref must be a mapping")
	}
	keys, err := mappingKeys(node)
	if err != nil {
		return KeyRef{}, err
	}
	keyNode, ok := keys["key"]
	if !ok {
		return KeyRef{}, fmt.Errorf("key is required")
	}
	key, err := scalarText(keyNode)
	if err != nil {
		return KeyRef{}, fmt.Errorf("key: %w", err)
	}
	if !keyRX.MatchString(key) {
		return KeyRef{}, fmt.Errorf("key %q does not match validation.key_pattern", key)
	}
	ref := KeyRef{Key: key}
	if docNode, ok := keys["document"]; ok {
		doc, err := scalarText(docNode)
		if err != nil {
			return KeyRef{}, fmt.Errorf("document: %w", err)
		}
		if err := repo.ValidateLogicalName(doc); err != nil {
			return KeyRef{}, fmt.Errorf("document: %w", err)
		}
		if _, ok := documents[doc]; !ok {
			return KeyRef{}, fmt.Errorf("document %q is not listed in documents", doc)
		}
		ref.Document = doc
	}
	for field := range keys {
		switch field {
		case "key", "document":
		default:
			return KeyRef{}, fmt.Errorf("unknown field %q", field)
		}
	}
	return ref, nil
}

func validateDefinitionShape(def Definition) error {
	forbidden := map[string]struct{}{}
	for _, key := range def.Forbidden {
		forbidden[key] = struct{}{}
	}
	var positive []string
	positive = append(positive, def.Required...)
	for _, rule := range def.Rules {
		switch rule.Kind {
		case RuleNonEmpty, RuleMinLength, RuleMatches:
			positive = append(positive, rule.Key)
		case RuleDistinct:
			positive = append(positive, rule.Distinct...)
		case RuleEquals, RuleNotEquals:
			for _, ref := range rule.Refs {
				positive = append(positive, ref.Key)
			}
		}
	}
	for _, key := range positive {
		if _, ok := forbidden[key]; ok {
			return fmt.Errorf("key %q is forbidden and also required by a rule", key)
		}
	}
	return nil
}

// rejectDuplicateRefs rejects equality rules that compare a value with itself.
// A duplicated ref would pass without checking two distinct secrets.
func rejectDuplicateRefs(refs []KeyRef, field string, documents []string) error {
	seen := map[string]struct{}{}
	for _, ref := range refs {
		id := refIdentity(ref, documents)
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%s: duplicate key ref %s", field, refLabel(ref))
		}
		seen[id] = struct{}{}
	}
	return nil
}

func refIdentity(ref KeyRef, documents []string) string {
	doc := ref.Document
	if doc == "" && len(documents) == 1 {
		doc = documents[0]
	}
	if doc == "" {
		return "merge\x00" + ref.Key
	}
	return doc + "\x00" + ref.Key
}

func validateKeyNames(keys []string, keyRX *regexp.Regexp, field string) error {
	seen := map[string]struct{}{}
	for _, key := range keys {
		if !keyRX.MatchString(key) {
			return fmt.Errorf("%s: key %q does not match validation.key_pattern", field, key)
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%s: duplicate key %q", field, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func readFromFile(configDir, rel string) ([]byte, error) {
	if rel == "" {
		return nil, fmt.Errorf("from must not be empty")
	}
	if filepath.IsAbs(rel) {
		return nil, fmt.Errorf("from path %q must be relative", rel)
	}
	clean := filepath.Clean(rel)
	if clean != rel {
		return nil, fmt.Errorf("from path %q is not normalized", rel)
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.Contains(rel, "..") {
		return nil, fmt.Errorf("from path %q must not traverse directories", rel)
	}
	absConfigDir, err := filepath.Abs(configDir)
	if err != nil {
		return nil, fmt.Errorf("resolve config directory: %w", err)
	}
	candidate := filepath.Join(absConfigDir, filepath.FromSlash(clean))
	resolvedConfigDir, err := filepath.EvalSymlinks(absConfigDir)
	if err != nil {
		if os.IsNotExist(err) {
			resolvedConfigDir = absConfigDir
		} else {
			return nil, fmt.Errorf("resolve config directory: %w", err)
		}
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("read from file %q: %w", rel, err)
		}
		return nil, fmt.Errorf("resolve from path %q: %w", rel, err)
	}
	relToConfig, err := filepath.Rel(resolvedConfigDir, resolvedCandidate)
	if err != nil {
		return nil, fmt.Errorf("from path %q escapes config directory", rel)
	}
	if relToConfig == ".." || strings.HasPrefix(relToConfig, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("from path %q escapes config directory", rel)
	}
	data, err := os.ReadFile(resolvedCandidate)
	if err != nil {
		return nil, fmt.Errorf("read from file %q: %w", rel, err)
	}
	return data, nil
}

func mappingKeys(node *yaml.Node) (map[string]*yaml.Node, error) {
	if node.Kind != yaml.MappingNode {
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

func rootMapping(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		if node.Content[0].Kind == yaml.MappingNode {
			return node.Content[0]
		}
		return nil
	}
	if node.Kind == yaml.MappingNode {
		return node
	}
	return nil
}

func stringSequence(node *yaml.Node, field string) ([]string, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s must be a sequence", field)
	}
	out := make([]string, 0, len(node.Content))
	for idx, item := range node.Content {
		text, err := scalarText(item)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, idx, err)
		}
		if text == "" {
			return nil, fmt.Errorf("%s[%d]: value must not be empty", field, idx)
		}
		out = append(out, text)
	}
	return out, nil
}

// scalarText returns the YAML source text for a scalar so contract condition
// values match how secret document strings are stored (for example true stays
// "true" instead of becoming a boolean).
func scalarText(node *yaml.Node) (string, error) {
	if node == nil {
		return "", fmt.Errorf("value is required")
	}
	if node.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("expected a scalar value")
	}
	return node.Value, nil
}

func intScalar(node *yaml.Node) (int, error) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return 0, fmt.Errorf("expected an integer scalar")
	}
	var value int
	if err := node.Decode(&value); err != nil {
		return 0, err
	}
	return value, nil
}

func boolScalarTrue(node *yaml.Node) (bool, error) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false, fmt.Errorf("expected a boolean scalar")
	}
	var value bool
	if err := node.Decode(&value); err != nil {
		return false, err
	}
	return value, nil
}

func isNullNode(node *yaml.Node) bool {
	return node != nil && node.Tag == "!!null"
}
