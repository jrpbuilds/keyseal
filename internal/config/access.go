package config

import (
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/jrpbuilds/keyseal/internal/repo"
	"gopkg.in/yaml.v3"
)

// AccessProfile scopes which logical documents doctor and verify validate for a
// role. Recipients are optional public age keys used only by
// --identity-profile availability checks. Private identity material must never
// appear here.
type AccessProfile struct {
	Include    []string
	Exclude    []string
	Recipients []string
}

// AccessProfileProblem records one access_profiles definition failure.
// Messages must never embed rejected secret values.
type AccessProfileProblem struct {
	Name    string
	Message string
}

// Error formats the problem for Validate fail-closed callers.
func (p AccessProfileProblem) Error() string {
	if p.Name == "" {
		return fmt.Sprintf("access_profiles: %s", p.Message)
	}
	return fmt.Sprintf("access_profiles.%s: %s", p.Name, p.Message)
}

// FirstAccessProfileProblem returns the first access profile problem, if any.
func FirstAccessProfileProblem(problems []AccessProfileProblem) error {
	if len(problems) == 0 {
		return nil
	}
	return problems[0]
}

// Matches reports whether logical is included by this profile.
// Exclude wins. Empty include means all documents, then subtract exclude.
func (p AccessProfile) Matches(logical string) (bool, error) {
	excluded, err := repo.MatchesAnyLogicalGlob(logical, p.Exclude)
	if err != nil {
		return false, err
	}
	if excluded {
		return false, nil
	}
	if len(p.Include) == 0 {
		return true, nil
	}
	return repo.MatchesAnyLogicalGlob(logical, p.Include)
}

// LoadAccessProfilesFromConfigYAML strictly decodes the top-level
// access_profiles map. Failures are recorded as problems so LoadLenient can
// surface them in doctor without aborting the rest of the load.
func LoadAccessProfilesFromConfigYAML(data []byte) (map[string]AccessProfile, []AccessProfileProblem, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("parse config yaml: %w", err)
	}
	mapping := rootMapping(&root)
	if mapping == nil {
		return map[string]AccessProfile{}, nil, nil
	}

	node, ok := mappingChild(mapping, "access_profiles")
	if !ok || node == nil || isNullNode(node) {
		return map[string]AccessProfile{}, nil, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("access_profiles must be a mapping")
	}

	out := map[string]AccessProfile{}
	var problems []AccessProfileProblem
	seen := map[string]struct{}{}

	for i := 0; i < len(node.Content)-1; i += 2 {
		name := node.Content[i].Value
		body := node.Content[i+1]

		if _, dup := seen[name]; dup {
			problems = append(problems, AccessProfileProblem{
				Name:    name,
				Message: "duplicate access profile name",
			})
			continue
		}
		seen[name] = struct{}{}

		if strings.TrimSpace(name) == "" {
			problems = append(problems, AccessProfileProblem{
				Message: "access profile name must not be empty",
			})
			continue
		}

		profile, err := decodeAccessProfile(body)
		if err != nil {
			problems = append(problems, AccessProfileProblem{
				Name:    name,
				Message: err.Error(),
			})
			continue
		}
		out[name] = profile
	}

	return out, problems, nil
}

func decodeAccessProfile(node *yaml.Node) (AccessProfile, error) {
	if node == nil || isNullNode(node) {
		return AccessProfile{}, fmt.Errorf("profile body is required")
	}
	if node.Kind != yaml.MappingNode {
		return AccessProfile{}, fmt.Errorf("profile body must be a mapping")
	}
	// Scan before field decode so private key material is rejected with a fixed
	// message and never appears in field-specific parse errors.
	if containsSecretKeyMaterial(node) {
		return AccessProfile{}, fmt.Errorf("private identity material is not allowed")
	}

	keys, err := mappingKeys(node)
	if err != nil {
		return AccessProfile{}, err
	}
	for key := range keys {
		switch key {
		case "include", "exclude", "recipients":
		default:
			return AccessProfile{}, fmt.Errorf("unknown field %q", key)
		}
	}

	include, err := optionalStringSequence(keys["include"], "include")
	if err != nil {
		return AccessProfile{}, err
	}
	exclude, err := optionalStringSequence(keys["exclude"], "exclude")
	if err != nil {
		return AccessProfile{}, err
	}
	recipients, err := optionalStringSequence(keys["recipients"], "recipients")
	if err != nil {
		return AccessProfile{}, err
	}
	if len(include) == 0 && len(exclude) == 0 {
		return AccessProfile{}, fmt.Errorf("include or exclude is required")
	}

	for _, pattern := range include {
		if err := repo.ValidateLogicalGlob(pattern); err != nil {
			return AccessProfile{}, fmt.Errorf("include: %w", err)
		}
	}
	for _, pattern := range exclude {
		if err := repo.ValidateLogicalGlob(pattern); err != nil {
			return AccessProfile{}, fmt.Errorf("exclude: %w", err)
		}
	}
	for _, recipient := range recipients {
		if err := validatePublicAgeRecipient(recipient); err != nil {
			return AccessProfile{}, err
		}
	}

	return AccessProfile{
		Include:    include,
		Exclude:    exclude,
		Recipients: recipients,
	}, nil
}

// validatePublicAgeRecipient accepts only public age recipients. Parse errors
// from the age library can quote the input, so callers always see a fixed
// message that does not echo the rejected value.
func validatePublicAgeRecipient(recipient string) error {
	trimmed := strings.TrimSpace(recipient)
	if trimmed == "" {
		return fmt.Errorf("recipients entries must not be empty")
	}
	if strings.Contains(strings.ToUpper(trimmed), "AGE-SECRET-KEY-") {
		return fmt.Errorf("private identity material is not allowed")
	}

	var err error
	switch {
	case strings.HasPrefix(trimmed, "age1pq1"):
		_, err = age.ParseHybridRecipient(trimmed)
	case strings.HasPrefix(trimmed, "age1"):
		_, err = age.ParseX25519Recipient(trimmed)
	default:
		return fmt.Errorf("recipients entry is not a valid age recipient")
	}
	if err != nil {
		return fmt.Errorf("recipients entry is not a valid age recipient")
	}
	return nil
}

func containsSecretKeyMaterial(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode {
		return strings.Contains(strings.ToUpper(node.Value), "AGE-SECRET-KEY-")
	}
	for _, child := range node.Content {
		if containsSecretKeyMaterial(child) {
			return true
		}
	}
	return false
}
