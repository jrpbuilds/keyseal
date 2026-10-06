package cli

import (
	"github.com/jrpbuilds/keyseal/internal/mutate"
	"github.com/spf13/cobra"
)

func newGenerateCommand() *cobra.Command {
	var byteCount int
	var encoding string
	var commitConfig commitFlags

	cmd := &cobra.Command{
		Use:   "generate <logical-name> <KEY>...",
		Short: "Set keys to cryptographically secure random values",
		Long: "Set one or more keys to independent random values from the operating system's secure random source.\n" +
			"Each value is --bytes random bytes encoded as base64url (URL-safe, unpadded), base64, or hex.\n" +
			"Existing keys are replaced. Generated values are never printed.",
		Example: "  keyseal generate production/app-next SAAS_TRIAL_FINGERPRINT_KEY --bytes 32\n" +
			"  keyseal generate production/app-next DB_PASSWORD REDIS_PASSWORD --encoding hex",
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
			values := make(map[string]string, len(keys))
			for _, key := range keys {
				value, err := mutate.Generate(byteCount, encoding)
				if err != nil {
					return err
				}
				values[key] = value
			}
			return m.update(cmd, logical, defaultCommitMessageForSecretGenerate(logical), func(doc *mutate.Document) ([]mutate.Change, error) {
				changes := make([]mutate.Change, 0, len(keys))
				for _, key := range keys {
					changes = append(changes, mutate.Change{Key: key, Action: doc.Set(key, values[key])})
				}
				return changes, nil
			})
		},
	}
	cmd.Flags().IntVar(&byteCount, "bytes", mutate.DefaultGenerateBytes, "Number of random bytes per value (16-1024)")
	cmd.Flags().StringVar(&encoding, "encoding", mutate.DefaultEncoding, "Value encoding: base64url, base64, or hex")
	bindCommitFlags(cmd, &commitConfig)
	return cmd
}
