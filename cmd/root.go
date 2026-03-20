package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cloudFlag         string
	tenantFlag        string
	outputFlag        string
	jsonFileFlag      string
	subscriptionsFlag string
	includeGroupsFlag bool
	verboseFlag       bool
	authMethodFlag    string
	fileFlag          string // --file: path to file with identity IDs/patterns
	typeFlag          string // --type: identity type filter
	exportFlag        string // --export: export file path (format from extension)
	perIdentityFlag   bool   // --per-identity: separate output per identity
	maxResultsFlag    int    // --max-results: max identities from pattern search
	concurrencyFlag   int    // --concurrency: max concurrent identity checks
)

var rootCmd = &cobra.Command{
	Use:   "azure-rbac-inventory",
	Short: "Azure RBAC Inventory — check RBAC assignments and access packages for any Azure identity",
	Long: `Azure RBAC Inventory is a CLI tool that resolves any Azure identity (user, SPN, 
managed identity, app registration, group) by object ID or app ID and reports:

  • Azure RBAC role assignments across all subscriptions
  • Entra ID directory role assignments
  • Access package assignments (Identity Governance)
  • Pending/denied access package requests
  • Group memberships (direct and transitive)

Supports both Azure Commercial and Azure Government clouds.`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cloudFlag, "cloud", "AzureCloud", "Azure cloud name (AzureCloud|AzureUSGovernment|AzureChinaCloud)")
	rootCmd.PersistentFlags().StringVar(&tenantFlag, "tenant", "", "Tenant ID (uses default from credential if not set)")
	rootCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "table", "Output format (table|json|csv|markdown)")
	rootCmd.PersistentFlags().StringVar(&jsonFileFlag, "json-file", "", "Export results to JSON file")
	rootCmd.PersistentFlags().StringVar(&subscriptionsFlag, "subscriptions", "", "Comma-separated subscription IDs (default: all accessible)")
	rootCmd.PersistentFlags().BoolVar(&includeGroupsFlag, "include-groups", false, "Include transitive group membership RBAC assignments")
	rootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVar(&authMethodFlag, "auth", "default", "Authentication method (default|cli|interactive|device-code|env|managed-identity)")
	rootCmd.PersistentFlags().StringVar(&fileFlag, "file", "", "Read identity IDs/patterns from file (one per line)")
	rootCmd.PersistentFlags().StringVar(&typeFlag, "type", "all", "Identity type filter (all|spn|user|group|managed-identity|app)")
	rootCmd.PersistentFlags().StringVar(&exportFlag, "export", "", "Export to file (format auto-detected from extension: .csv/.html/.md/.xlsx/.json)")
	rootCmd.PersistentFlags().BoolVar(&perIdentityFlag, "per-identity", false, "Separate output/file per identity when processing multiple")
	rootCmd.PersistentFlags().IntVar(&maxResultsFlag, "max-results", 50, "Max identities to return from pattern search")
	rootCmd.PersistentFlags().IntVar(&concurrencyFlag, "concurrency", 10, "Max concurrent identity checks for batch processing")
}

// SetVersion sets the version string for the CLI.
func SetVersion(v string) {
	rootCmd.Version = v
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}
