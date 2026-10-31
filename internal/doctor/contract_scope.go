package doctor

import (
	"fmt"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/jrpbuilds/keyseal/internal/contract"
)

// ContractDocumentScope classifies a contract's documents under the active
// doctor/verify document selector.
type ContractDocumentScope string

const (
	ContractDocumentScopeFull     ContractDocumentScope = "full"
	ContractDocumentScopeIncluded ContractDocumentScope = "included"
	ContractDocumentScopeExcluded ContractDocumentScope = "excluded"
	ContractDocumentScopeMixed    ContractDocumentScope = "mixed"
)

// ClassifyContractDocuments reports how a contract's documents relate to opts.
// Selector conflicts and unknown profiles return an error; callers should treat
// that as a hard failure because doctor already reported the same issue.
func ClassifyContractDocuments(def contract.Definition, opts Options, cfg config.Config) (ContractDocumentScope, error) {
	filter, selectionFail := resolveDocumentFilter(opts, cfg)
	if selectionFail != nil {
		return "", fmt.Errorf("%s", selectionFail.Summary)
	}
	kind, _, err := classifyContractDocuments(def, filter)
	return kind, err
}

// classifyContractDocuments classifies def under an already-resolved filter and
// returns the in-scope document list for full/included outcomes. Doctor and
// verify both use this path so mixed-scope handling cannot drift.
func classifyContractDocuments(def contract.Definition, filter documentFilter) (ContractDocumentScope, []string, error) {
	if !filter.active {
		return ContractDocumentScopeFull, append([]string(nil), def.Documents...), nil
	}

	included := make([]string, 0, len(def.Documents))
	excluded := 0
	for _, logical := range def.Documents {
		ok, err := filter.includes(logical)
		if err != nil {
			return "", nil, err
		}
		if ok {
			included = append(included, logical)
			continue
		}
		excluded++
	}

	switch {
	case len(included) == 0:
		return ContractDocumentScopeExcluded, nil, nil
	case excluded == 0:
		return ContractDocumentScopeIncluded, included, nil
	default:
		return ContractDocumentScopeMixed, nil, nil
	}
}

// MixedContractCheck builds the shared doctor/verify failure for a contract
// that spans documents inside and outside the selected scope.
func MixedContractCheck(name string, def contract.Definition) CheckResult {
	return CheckResult{
		Name:     fmt.Sprintf("contract %q", name),
		Status:   StatusFail,
		Severity: SeverityError,
		Summary:  fmt.Sprintf("Contract %q spans documents inside and outside the selected scope", name),
		Details: []string{
			"Partial contract evaluation is not supported.",
			fmt.Sprintf("Documents: %s", strings.Join(def.Documents, ", ")),
		},
		Remediation: []string{
			"Widen the selected scope to cover every document listed by the contract, or split the contract.",
		},
	}
}
