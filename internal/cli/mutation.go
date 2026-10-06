package cli

import (
	"fmt"
	"regexp"

	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/jrpbuilds/keyseal/internal/mutate"
	"github.com/jrpbuilds/keyseal/internal/repo"
	"github.com/jrpbuilds/keyseal/internal/schema"
	"github.com/spf13/cobra"
)

// documentMutation holds the shared context for the non-interactive mutation
// commands: clone, set, unset, generate, and import.
type documentMutation struct {
	ctx    gitWorkflowContext
	opts   mutate.Options
	commit commitDecision
}

// prepareMutation loads config, resolves the commit decision, and checks SOPS
// before any secret input is read or any document is decrypted.
func prepareMutation(cmd *cobra.Command, flags commitFlags) (documentMutation, error) {
	ctx, err := loadGitWorkflowContext()
	if err != nil {
		return documentMutation{}, err
	}
	decision, err := resolveCommitDecision(cmd, ctx.Config, flags)
	if err != nil {
		return documentMutation{}, err
	}
	if decision.Enabled {
		if err := ensureRepoReadyForCommit(ctx); err != nil {
			return documentMutation{}, err
		}
	}
	if err := ensureSOPSAvailable(ctx.Config, ctx.CWD); err != nil {
		return documentMutation{}, err
	}
	return documentMutation{
		ctx: ctx,
		opts: mutate.Options{
			SOPSBinary: ctx.Config.SOPS.Binary,
			AgeKeyFile: config.ResolvePath(ctx.CWD, ctx.Config.SOPS.AgeKeyFile),
			Validation: validationOptions(ctx.Config),
		},
		commit: decision,
	}, nil
}

func (m documentMutation) target(logical string) (mutate.Target, error) {
	path, err := repo.LogicalNameToPath(m.ctx.KeysealRoot, logical, m.ctx.Config.Repository.EncryptedExtension)
	if err != nil {
		return mutate.Target{}, err
	}
	return mutate.Target{Logical: logical, Path: path}, nil
}

// update runs one transaction against logical, prints key names and actions
// (never values), and optionally commits only the updated document.
func (m documentMutation) update(cmd *cobra.Command, logical, defaultMessage string, apply func(*mutate.Document) ([]mutate.Change, error)) error {
	target, err := m.target(logical)
	if err != nil {
		return err
	}
	result, err := mutate.Update(m.opts, target, apply)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	for _, change := range result.Changes {
		fmt.Fprintf(out, "%s %s\n", change.Action, change.Key)
	}
	if !result.Written {
		fmt.Fprintf(out, "no changes; %s left untouched\n", logical)
		return nil
	}
	fmt.Fprintf(out, "updated %s\n", logical)
	return m.commitIfRequested(cmd, target.Path, defaultMessage)
}

func (m documentMutation) commitIfRequested(cmd *cobra.Command, path, defaultMessage string) error {
	if !m.commit.Enabled {
		return nil
	}
	message := m.commit.Message
	if message == "" {
		message = defaultMessage
	}
	if err := commitPaths(m.ctx, []string{path}, message); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "committed Git change: %s\n", message)
	return nil
}

// validateKeyNames checks requested keys against the configured key pattern
// before anything is decrypted, and rejects repeated keys.
func validateKeyNames(keys []string, opts schema.ValidationOptions) error {
	rx, err := regexp.Compile(opts.KeyPattern)
	if err != nil {
		return fmt.Errorf("invalid key pattern: %w", err)
	}
	seen := map[string]bool{}
	for _, key := range keys {
		if !rx.MatchString(key) {
			return fmt.Errorf("invalid env key %q: must match %s", key, opts.KeyPattern)
		}
		if seen[key] {
			return fmt.Errorf("key %s is listed more than once", key)
		}
		seen[key] = true
	}
	return nil
}

func validationOptions(cfg config.Config) schema.ValidationOptions {
	opts := schema.DefaultValidationOptions()
	opts.RequireValues = cfg.Validation.RequireValues
	opts.KeyPattern = cfg.Validation.KeyPattern
	return opts
}
