package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jrpbuilds/keyseal/internal/gitutil"
	"github.com/jrpbuilds/keyseal/internal/observe"
	"github.com/spf13/cobra"
)

// observeFlags are the flags shared by every command that prints an
// observe.Report.
type observeFlags struct {
	json          bool
	keys          []string
	showLength    bool
	showType      bool
	fingerprint   bool
	assertEqual   bool
	assertUnequal bool
}

// semanticOnlyFlags are the flags diff accepts only together with --semantic.
var semanticOnlyFlags = []string{"to", "json", "key", "show-length", "show-type", "fingerprint", "assert-equal", "assert-unequal"}

func (f *observeFlags) bindReportFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.json, "json", false, "Emit structured JSON for CI or scripts")
	cmd.Flags().StringArrayVar(&f.keys, "key", nil, "Limit the report to this key; repeat for several keys")
	cmd.Flags().BoolVar(&f.showLength, "show-length", false, "Also report each value's length in characters")
	cmd.Flags().BoolVar(&f.showType, "show-type", false, "Also report each value's YAML type")
	cmd.Flags().BoolVar(&f.fingerprint, "fingerprint", false, "Also report a keyed fingerprint of each value; needs "+observe.FingerprintKeyEnv)
}

func (f *observeFlags) bindAssertFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.assertEqual, "assert-equal", false, "Exit 1 unless every compared key is equal")
	cmd.Flags().BoolVar(&f.assertUnequal, "assert-unequal", false, "Exit 1 unless at least one compared key differs")
}

func (f observeFlags) option() (observe.Option, error) {
	if f.assertEqual && f.assertUnequal {
		return observe.Option{}, errors.New("--assert-equal and --assert-unequal cannot be used together")
	}
	for _, key := range f.keys {
		if key == "" {
			return observe.Option{}, errors.New("--key requires a non-empty key name")
		}
	}
	opt := observe.Option{
		Keys:        f.keys,
		ShowLength:  f.showLength,
		ShowType:    f.showType,
		Fingerprint: f.fingerprint,
	}
	switch {
	case f.assertEqual:
		opt.Assertion = observe.AssertEqual
	case f.assertUnequal:
		opt.Assertion = observe.AssertUnequal
	}
	return opt, nil
}

// newObserveScope loads config and, only when a revision will be read, the Git
// root. Comparing two worktree documents therefore works outside a repository.
func newObserveScope(needsGit bool) (*observe.Scope, error) {
	cfg, cwd, err := loadConfigFromCWD()
	if err != nil {
		return nil, err
	}
	gitRoot := ""
	if needsGit {
		gitRoot, err = gitutil.RepoRoot("git", cwd)
		if err != nil {
			return nil, err
		}
	}
	return observe.New(cwd, cfg, gitRoot), nil
}

// finishReport writes the report body whether or not it passed, then turns a
// failed report into exit 1 with no second message on stderr.
func finishReport(cmd *cobra.Command, asJSON bool, rep observe.Report) error {
	if asJSON {
		body, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal report json: %w", err)
		}
		if _, err := cmd.OutOrStdout().Write(append(body, '\n')); err != nil {
			return err
		}
	} else if _, err := fmt.Fprint(cmd.OutOrStdout(), rep.Text()); err != nil {
		return err
	}
	if !rep.Passed() {
		return commandExitError{code: 1}
	}
	return nil
}
