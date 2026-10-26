package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jrpbuilds/keyseal/internal/config"
	"github.com/spf13/cobra"
)

func newInitCommand() *cobra.Command {
	var profile string
	var force bool
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Bootstrap a Keyseal repository layout",
		Long: "Create keyseal.yaml, .sops.yaml, and the standard production/staging directory layout.\n" +
			"Use --dry-run to inspect the planned changes before writing anything.",
		Example: "  keyseal init\n" +
			"  keyseal init --dry-run\n" +
			"  keyseal init --force",
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			files := map[string]string{
				filepath.Join(cwd, "keyseal.yaml"): defaultConfigYAML(profile),
				filepath.Join(cwd, ".sops.yaml"):   defaultSOPSYAML(),
			}
			dirs := []string{
				filepath.Join(cwd, "production/platform"),
				filepath.Join(cwd, "production/infra"),
				filepath.Join(cwd, "production/tenants"),
				filepath.Join(cwd, "staging/platform"),
				filepath.Join(cwd, "staging/infra"),
				filepath.Join(cwd, "staging/tenants"),
			}

			for path := range files {
				if _, err := os.Stat(path); err == nil && !force {
					return fmt.Errorf("%s already exists; use --force to overwrite", filepath.Base(path))
				}
			}
			for _, dir := range dirs {
				if _, err := os.Stat(dir); err == nil && !force {
					return fmt.Errorf("%s already exists; use --force to continue", dir)
				}
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "profile: %s\n", profile)
				for _, dir := range dirs {
					fmt.Fprintf(cmd.OutOrStdout(), "create dir  %s\n", dir)
				}
				for path := range files {
					fmt.Fprintf(cmd.OutOrStdout(), "create file %s\n", path)
				}
				return nil
			}

			for _, dir := range dirs {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return fmt.Errorf("create directory %s: %w", dir, err)
				}
			}
			for path, content := range files {
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					return fmt.Errorf("write %s: %w", path, err)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "initialized Keyseal repository with profile %q\n", profile)
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "default", "Profile name to seed in keyseal.yaml")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing starter files and continue if directories exist")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be created without writing")
	return cmd
}

func defaultConfigYAML(profile string) string {
	cfg := config.Default()
	return strings.TrimSpace(fmt.Sprintf(`
version: %d

repository:
  root: %s
  encrypted_extension: %s

sops:
  binary: %s
  age_binary: %s
  age_key_file: %s

git:
  auto_commit: %t

defaults:
  output_format: %s
  output_dir: %s
  file_mode: %q

validation:
  require_values: %t
  key_pattern: %q

# Optional: require a minimum Keyseal binary version for this repository.
# requirements:
#   keyseal: ">=1.1.0"

profiles:
  %s:
    renders: []
`, cfg.Version, cfg.Repository.Root, cfg.Repository.EncryptedExtension, cfg.SOPS.Binary, cfg.SOPS.AgeBinary, cfg.SOPS.AgeKeyFile, cfg.Git.AutoCommit, cfg.Defaults.OutputFormat, cfg.Defaults.OutputDir, cfg.Defaults.FileMode, cfg.Validation.RequireValues, cfg.Validation.KeyPattern, profile)) + "\n"
}

func defaultSOPSYAML() string {
	return `creation_rules:
  - path_regex: production/.*\.enc\.yaml$
    age: age1REPLACE_ME,age1RECOVERY_REPLACE_ME

  - path_regex: staging/.*\.enc\.yaml$
    age: age1REPLACE_ME,age1RECOVERY_REPLACE_ME
`
}
