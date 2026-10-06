package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/mutate"
	"github.com/spf13/cobra"
)

func newImportCommand() *cobra.Command {
	var envFile string
	var keys []string
	var commitConfig commitFlags

	cmd := &cobra.Command{
		Use:   "import <logical-name> --from-env-file <path> --keys KEY[,KEY...]",
		Short: "Import selected values from a dotenv file",
		Long: "Copy the listed keys from a dotenv file into an encrypted document as a single transaction.\n" +
			"Only keys named in --keys are imported. If any listed key is missing or empty in the file, nothing is changed.\n" +
			"Supported lines: KEY=value, KEY=\"escaped\", KEY='literal', optional `export` prefix, and # comment lines.\n" +
			"Keyseal never modifies or deletes the source file.",
		Example: "  keyseal import production/app-next --from-env-file ./intake.env --keys STRIPE_SECRET_KEY,STRIPE_PUBLIC_KEY",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logical := args[0]
			if envFile == "" {
				return errors.New("--from-env-file is required")
			}
			if len(keys) == 0 {
				return errors.New("--keys is required; list the keys to import")
			}
			m, err := prepareMutation(cmd, commitConfig)
			if err != nil {
				return err
			}
			if err := validateKeyNames(keys, m.opts.Validation); err != nil {
				return err
			}
			parsed, err := mutate.ReadDotenvFile(envFile)
			if err != nil {
				return err
			}
			var missing, empty []string
			for _, key := range keys {
				value, ok := parsed[key]
				switch {
				case !ok:
					missing = append(missing, key)
				case value == "":
					empty = append(empty, key)
				}
			}
			if len(missing) > 0 {
				return fmt.Errorf("not found in env file: %s; nothing changed", strings.Join(missing, ", "))
			}
			if len(empty) > 0 {
				return fmt.Errorf("empty in env file: %s; nothing changed", strings.Join(empty, ", "))
			}
			return m.update(cmd, logical, defaultCommitMessageForSecretImport(logical), func(doc *mutate.Document) ([]mutate.Change, error) {
				changes := make([]mutate.Change, 0, len(keys))
				for _, key := range keys {
					changes = append(changes, mutate.Change{Key: key, Action: doc.Set(key, parsed[key])})
				}
				return changes, nil
			})
		},
	}
	cmd.Flags().StringVar(&envFile, "from-env-file", "", "Dotenv file to read values from")
	cmd.Flags().StringSliceVar(&keys, "keys", nil, "Comma-separated keys to import")
	bindCommitFlags(cmd, &commitConfig)
	return cmd
}
