package cli

import (
	"fmt"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/mutate"
	"github.com/spf13/cobra"
)

func newUnsetCommand() *cobra.Command {
	var commitConfig commitFlags

	cmd := &cobra.Command{
		Use:   "unset <logical-name> <KEY>...",
		Short: "Remove keys from an encrypted document",
		Long: "Remove one or more keys from an encrypted document as a single transaction.\n" +
			"If any requested key is not present, the command fails and nothing is changed.\n" +
			"The document is re-encrypted and verified before it replaces the original.",
		Example: "  keyseal unset production/app-next TWILIO_TOKEN\n" +
			"  keyseal unset production/app-next TWILIO_SID TWILIO_TOKEN -m \"Remove Twilio credentials\"",
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			logical, keys := args[0], args[1:]
			m, err := prepareMutation(cmd, commitConfig)
			if err != nil {
				return err
			}
			if err := validateKeyNames(keys, m.opts.Validation); err != nil {
				return err
			}
			return m.update(cmd, logical, defaultCommitMessageForSecretUnset(logical), func(doc *mutate.Document) ([]mutate.Change, error) {
				present := doc.Values()
				var missing []string
				for _, key := range keys {
					if _, ok := present[key]; !ok {
						missing = append(missing, key)
					}
				}
				if len(missing) > 0 {
					return nil, fmt.Errorf("not present in %s: %s; nothing changed", logical, strings.Join(missing, ", "))
				}
				changes := make([]mutate.Change, 0, len(keys))
				for _, key := range keys {
					doc.Unset(key)
					changes = append(changes, mutate.Change{Key: key, Action: mutate.Removed})
				}
				return changes, nil
			})
		},
	}
	bindCommitFlags(cmd, &commitConfig)
	return cmd
}
