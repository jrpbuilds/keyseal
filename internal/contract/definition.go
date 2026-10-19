package contract

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jrpbuilds/keyseal/internal/repo"
)

// FirstProblem returns the first load/definition problem, if any.
func FirstProblem(problems []Problem) error {
	if len(problems) == 0 {
		return nil
	}
	return problems[0]
}

// DocumentExistenceProblems reports contracts whose logical documents are
// missing on disk. It only stats paths. It does not read or decrypt file
// contents, so plaintext secret bytes never enter this check.
func DocumentExistenceProblems(def Definition, repoRoot, encryptedExt string) []Problem {
	var problems []Problem
	for _, logical := range def.Documents {
		path, err := repo.LogicalNameToPath(repoRoot, logical, encryptedExt)
		if err != nil {
			problems = append(problems, Problem{
				Name:    def.Name,
				Message: fmt.Sprintf("document %q: %v", logical, err),
			})
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				problems = append(problems, Problem{
					Name:    def.Name,
					Message: fmt.Sprintf("document %q is missing at %s", logical, filepath.ToSlash(path)),
				})
				continue
			}
			problems = append(problems, Problem{
				Name:    def.Name,
				Message: fmt.Sprintf("document %q at %s could not be inspected: %v", logical, filepath.ToSlash(path), err),
			})
			continue
		}
		if info.IsDir() {
			problems = append(problems, Problem{
				Name:    def.Name,
				Message: fmt.Sprintf("document %q is a directory at %s", logical, filepath.ToSlash(path)),
			})
		}
	}
	return problems
}
