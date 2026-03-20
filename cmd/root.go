// Package cmd implements the CLI commands for azure-rbac-inventory.
package cmd

import (
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	cloudFlag                 string
	tenantFlag                string
	outputFlag                string
	jsonFileFlag              string
	subscriptionsFlag         string
	includeGroupRBACFlag      bool
	includeAccessPackagesFlag bool
	verboseFlag               bool
	authMethodFlag            string
	fileFlag                  string        // --file: path to file with identity IDs/patterns
	typeFlag                  string        // --type: identity type filter
	exportFlag                string        // --export: export file path (format from extension)
	perIdentityFlag           bool          // --per-identity: separate output per identity
	maxResultsFlag            int           // --max-results: max identities from pattern search
	concurrencyFlag           int           // --concurrency: max concurrent identity checks
	timeoutFlag               time.Duration // --timeout: global execution timeout
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
	rootCmd.PersistentFlags().StringVar(&cloudFlag, "cloud", envOrDefault("AZURE_RBAC_CLOUD", "AzureCloud"), "Azure cloud name (AzureCloud|AzureUSGovernment|AzureChinaCloud)")
	rootCmd.PersistentFlags().StringVar(&tenantFlag, "tenant", os.Getenv("AZURE_TENANT_ID"), "Tenant ID (uses default from credential if not set)")
	rootCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "table", "Output format (table|json|csv|markdown)")
	rootCmd.PersistentFlags().StringVar(&jsonFileFlag, "json-file", "", "Export results to JSON file")
	rootCmd.PersistentFlags().StringVar(&subscriptionsFlag, "subscriptions", os.Getenv("AZURE_RBAC_SUBSCRIPTIONS"), "Comma-separated subscription IDs (default: all accessible)")
	rootCmd.PersistentFlags().BoolVar(&includeGroupRBACFlag, "include-group-rbac", false, "Also query RBAC role assignments inherited through group memberships (group list always shown)")
	rootCmd.PersistentFlags().BoolVar(&includeAccessPackagesFlag, "include-access-packages", false, "Query access package assignments and requests (requires EntitlementManagement.Read.All)")
	rootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVar(&authMethodFlag, "auth", envOrDefault("AZURE_RBAC_AUTH", "interactive"), "Authentication method (interactive|device-code|environment|managed-identity|azurecli)")
	rootCmd.PersistentFlags().StringVar(&fileFlag, "file", "", "Read identity IDs/patterns from file (one per line)")
	rootCmd.PersistentFlags().StringVar(&typeFlag, "type", "all", "Identity type filter (all|spn|user|group|managed-identity|app)")
	rootCmd.PersistentFlags().StringVar(&exportFlag, "export", "", "Export to file (format auto-detected from extension: .csv/.html/.md/.xlsx/.json)")
	rootCmd.PersistentFlags().BoolVar(&perIdentityFlag, "per-identity", false, "Separate output/file per identity when processing multiple")
	rootCmd.PersistentFlags().IntVar(&maxResultsFlag, "max-results", 50, "Max identities to return from pattern search")
	rootCmd.PersistentFlags().IntVar(&concurrencyFlag, "concurrency", 10, "Max concurrent identity checks for batch processing")
	rootCmd.PersistentFlags().DurationVar(&timeoutFlag, "timeout", 30*time.Minute, "Global execution timeout (e.g. 10m, 1h)")
}

// envOrDefault returns the value of an environment variable, or the fallback if unset.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// SetVersion sets the version string for the CLI.
func SetVersion(v string) {
	rootCmd.Version = v
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
