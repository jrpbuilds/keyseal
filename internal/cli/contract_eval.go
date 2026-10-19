package cli

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/jrpbuilds/keyseal/internal/contract"
	"github.com/jrpbuilds/keyseal/internal/doctor"
	"github.com/jrpbuilds/keyseal/internal/repo"
	"github.com/jrpbuilds/keyseal/internal/schema"
	"github.com/jrpbuilds/keyseal/internal/secretfile"
	"github.com/jrpbuilds/keyseal/internal/sopsutil"
)

// loadContractDocuments decrypts every logical document listed by def.
// Operational failures return a single load violation message and no docs.
func loadContractDocuments(cfg config.Config, cwd string, def contract.Definition) (map[string]schema.EnvSecretDocument, *contract.Violation) {
	opts := validationOptions(cfg)
	root := cfg.RepoRoot(cwd)
	ageKeyFile := config.ResolvePath(cwd, cfg.SOPS.AgeKeyFile)
	paths := make([]string, 0, len(def.Documents))
	// Classify every document before decrypting so a missing, placeholder, or
	// plaintext file does not cause sibling documents to be decrypted.
	for _, logical := range def.Documents {
		path, err := repo.LogicalNameToPath(root, logical, cfg.Repository.EncryptedExtension)
		if err != nil {
			v := contract.Violation{
				Rule:    string(contract.RuleLoad),
				Keys:    []string{},
				Message: fmt.Sprintf("document %q could not be resolved: %v", logical, err),
			}
			return nil, &v
		}
		classified, err := secretfile.Classify(path)
		if err != nil {
			v := contract.Violation{
				Rule:    string(contract.RuleLoad),
				Keys:    []string{},
				Message: fmt.Sprintf("document %q could not be inspected: %v", logical, err),
			}
			return nil, &v
		}
		switch classified.State {
		case secretfile.StateMissing:
			v := contract.Violation{
				Rule:    string(contract.RuleLoad),
				Keys:    []string{},
				Message: fmt.Sprintf("document %q is missing at %s", logical, filepath.ToSlash(path)),
			}
			return nil, &v
		case secretfile.StatePlaceholder:
			v := contract.Violation{
				Rule:    string(contract.RuleLoad),
				Keys:    []string{},
				Message: fmt.Sprintf("document %q is an empty placeholder and cannot be evaluated", logical),
			}
			return nil, &v
		case secretfile.StatePlaintext:
			v := contract.Violation{
				Rule:    string(contract.RuleLoad),
				Keys:    []string{},
				Message: fmt.Sprintf("document %q is plaintext at an encrypted path", logical),
			}
			return nil, &v
		}
		paths = append(paths, path)
	}
	docs := make(map[string]schema.EnvSecretDocument, len(def.Documents))
	for i, logical := range def.Documents {
		plaintext, err := sopsutil.DecryptFile(paths[i], "yaml", ageKeyFile)
		if err != nil {
			v := contract.Violation{
				Rule:    string(contract.RuleLoad),
				Keys:    []string{},
				Message: fmt.Sprintf("document %q could not be decrypted", logical),
			}
			return nil, &v
		}
		doc, _, err := schema.ParseYAMLDocument(plaintext)
		if err != nil {
			v := contract.Violation{
				Rule:    string(contract.RuleLoad),
				Keys:    []string{},
				Message: fmt.Sprintf("document %q is not valid YAML", logical),
			}
			return nil, &v
		}
		if err := doc.Validate(opts); err != nil {
			v := contract.Violation{
				Rule:    string(contract.RuleLoad),
				Keys:    []string{},
				Message: fmt.Sprintf("document %q failed schema validation", logical),
			}
			return nil, &v
		}
		docs[logical] = doc
	}
	return docs, nil
}

// evaluateContract loads documents for def and returns all violations.
func evaluateContract(cfg config.Config, cwd string, def contract.Definition) []contract.Violation {
	docs, loadViolation := loadContractDocuments(cfg, cwd, def)
	if loadViolation != nil {
		return []contract.Violation{*loadViolation}
	}
	return contract.Evaluate(def, docs)
}

// appendContractEvaluationChecks evaluates every configured contract and
// replaces doctor definition-OK contract checks with evaluation results so
// verify reports one check per contract name.
func appendContractEvaluationChecks(cfg config.Config, cwd string, result *doctor.Result) {
	if len(cfg.Contracts) == 0 {
		return
	}
	kept := result.Checks[:0]
	for _, check := range result.Checks {
		if isContractDefinitionOK(check) {
			continue
		}
		kept = append(kept, check)
	}
	result.Checks = kept

	for _, name := range sortedContractNames(cfg) {
		def := cfg.Contracts[name]
		violations := evaluateContract(cfg, cwd, def)
		checkName := fmt.Sprintf("contract %q", name)
		if len(violations) == 0 {
			result.Add(doctor.CheckResult{
				Name:     checkName,
				Status:   doctor.StatusOK,
				Severity: doctor.SeverityInformational,
				Summary:  "Contract evaluation passed",
			})
			continue
		}
		details := make([]string, 0, len(violations))
		for _, violation := range violations {
			details = append(details, violation.Message)
		}
		result.Add(doctor.CheckResult{
			Name:     checkName,
			Status:   doctor.StatusFail,
			Severity: doctor.SeverityError,
			Summary:  fmt.Sprintf("Contract %q failed evaluation", name),
			Details:  details,
			Remediation: []string{
				fmt.Sprintf("Update the secrets referenced by contract %q so every rule passes, then rerun `keyseal verify`.", name),
			},
		})
	}
}

func isContractDefinitionOK(check doctor.CheckResult) bool {
	return check.Status == doctor.StatusOK && strings.HasPrefix(check.Name, `contract "`)
}

func sortedContractNames(cfg config.Config) []string {
	names := make([]string, 0, len(cfg.Contracts))
	for name := range cfg.Contracts {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
