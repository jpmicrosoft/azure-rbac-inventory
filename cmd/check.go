package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/auth"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/checker"
	cloudenv "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/output"
	reportpkg "github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

var checkCmd = &cobra.Command{
	Use:   "check [object-id-or-app-id-or-pattern]",
	Short: "Check RBAC and access package assignments for an identity",
	Long: `Resolves the given object ID, app ID, or display name pattern to an Azure
identity, then queries all RBAC role assignments, Entra ID directory roles,
and group memberships.

Use --include-access-packages to also query access package assignments and
pending requests (requires EntitlementManagement.Read.All permission).
Use --file to supply a list of identity IDs or patterns from a file (one per line).
Use --include-group-rbac to also query RBAC role assignments inherited through
transitive group memberships (group memberships are always listed regardless).`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 && fileFlag == "" {
			return fmt.Errorf("requires either an identity ID/pattern argument or --file flag")
		}
		if len(args) > 0 && fileFlag != "" {
			return fmt.Errorf("cannot use both positional argument and --file flag")
		}
		if len(args) > 1 {
			return fmt.Errorf("accepts at most 1 arg, received %d", len(args))
		}
		return nil
	},
	RunE: runCheck,
}

func init() {
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	if maxResultsFlag <= 0 {
		return fmt.Errorf("--max-results must be a positive integer, got %d", maxResultsFlag)
	}
	if concurrencyFlag <= 0 || concurrencyFlag > 50 {
		return fmt.Errorf("--concurrency must be between 1 and 50, got %d", concurrencyFlag)
	}

	// Collect input identities from positional arg or --file
	var entries []identity.InputEntry
	if fileFlag != "" {
		var err error
		entries, err = identity.ParseInputFile(fileFlag)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Read %d identities from file\n", len(entries))
	} else {
		entries = []identity.InputEntry{{ID: args[0]}}
	}

	// Resolve cloud environment
	env, ok := cloudenv.GetEnvironment(cloudFlag)
	if !ok {
		return fmt.Errorf("invalid cloud name %q — valid values: %v", cloudFlag, cloudenv.ValidCloudNames)
	}
	fmt.Fprintf(os.Stderr, "Cloud: %s\n", env.Name)

	// Create credential
	fmt.Fprint(os.Stderr, "Authenticating... ")
	cred, err := auth.GetCredential(env, tenantFlag, authMethodFlag)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	fmt.Fprintln(os.Stderr, "OK")

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag)
	defer cancel()

	// Pre-acquire tokens for both API scopes sequentially to avoid double browser prompts.
	// Also validates azurecli has required scopes. Skip for environment/managed-identity.
	if auth.NeedsPreAuth(authMethodFlag) {
		if err := auth.PreAuthenticate(ctx, cred, env, authMethodFlag); err != nil {
			return fmt.Errorf("pre-authentication failed: %w", err)
		}
	}

	// Resolve all inputs to concrete identity IDs (expand patterns)
	var resolvedIDs []string
	graphClient := graph.NewClient(cred, env)
	resolver := identity.NewResolver(graphClient)

	for _, entry := range entries {
		// Per-entry type overrides global --type flag
		searchType := typeFlag
		if entry.Type != "" && entry.Type != "all" {
			searchType = entry.Type
		}

		if entry.Label != "" {
			fmt.Fprintf(os.Stderr, "  [%s] ", entry.Label)
		}

		if identity.IsPattern(entry.ID) {
			fmt.Fprintf(os.Stderr, "Searching for identities matching: %s\n", entry.ID)
			results, err := resolver.Search(ctx, entry.ID, searchType, maxResultsFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: search for %q failed: %v\n", entry.ID, err)
				continue
			}
			if len(results) == 0 {
				fmt.Fprintf(os.Stderr, "Warning: no identities found matching %q\n", entry.ID)
				continue
			}
			fmt.Fprintf(os.Stderr, "  Found %d matching identities:\n", len(results))
			for i, r := range results {
				appInfo := ""
				if r.Identity.AppID != "" {
					appInfo = fmt.Sprintf("  AppID: %s", r.Identity.AppID)
				}
				fmt.Fprintf(os.Stderr, "    %d. %s  (%s)  %s%s\n", i+1, r.Identity.DisplayName, r.Identity.Type, r.Identity.ObjectID, appInfo)
				resolvedIDs = append(resolvedIDs, r.Identity.ObjectID)
			}
		} else {
			resolvedIDs = append(resolvedIDs, entry.ID)
		}
	}

	if len(resolvedIDs) == 0 {
		return fmt.Errorf("no identities to process")
	}
	const maxResolvedIdentities = 1000
	if len(resolvedIDs) > maxResolvedIdentities {
		return fmt.Errorf("pattern search resolved %d identities, exceeding maximum of %d; narrow your search patterns or reduce --max-results",
			len(resolvedIDs), maxResolvedIdentities)
	}
	fmt.Fprintf(os.Stderr, "\nProcessing %d identities...\n", len(resolvedIDs))

	// Process each identity
	baseCfg := checker.Config{
		Cloud:                 cloudFlag,
		TenantID:              tenantFlag,
		Subscriptions:         checker.ParseSubscriptions(subscriptionsFlag),
		IncludeGroups:         includeGroupRBACFlag,
		IncludeAccessPackages: includeAccessPackagesFlag,
		Verbose:               verboseFlag,
		OutputFormat:          outputFlag,
		JSONFile:              jsonFileFlag,
		ExportFile:            exportFlag,
		IdentityType:          typeFlag,
		MaxResults:            maxResultsFlag,
		Concurrency:           concurrencyFlag,
		PerIdentity:           perIdentityFlag,
	}

	var reports []*reportpkg.Report
	for i, id := range resolvedIDs {
		if len(resolvedIDs) > 1 {
			fmt.Fprintf(os.Stderr, "\n── Identity %d/%d ──\n", i+1, len(resolvedIDs))
		}
		cfg := baseCfg
		cfg.IdentityID = id
		rpt, err := checker.Run(ctx, cred, env, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to process %s: %v\n", id, err)
			continue
		}
		reports = append(reports, rpt)

		// In per-identity mode, render each report immediately
		if perIdentityFlag && len(resolvedIDs) > 1 {
			if err := renderOutput(rpt, baseCfg.OutputFormat); err != nil {
				return err
			}
			if exportFlag != "" {
				perFile := perIdentityFilename(exportFlag, rpt.Identity.DisplayName, i)
				if err := output.ExportFile(rpt, perFile); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: export failed for %s: %v\n", rpt.Identity.DisplayName, err)
				}
			}
		}
	}

	if len(reports) == 0 {
		return fmt.Errorf("all identity checks failed")
	}

	// Merge related identities (App Reg + SPN with same name)
	reports = reportpkg.MergeRelatedReports(reports)

	// Combined mode (default) or single identity
	if !perIdentityFlag || len(resolvedIDs) == 1 {
		if len(reports) == 1 {
			if err := renderOutput(reports[0], baseCfg.OutputFormat); err != nil {
				return err
			}
			if exportFlag != "" {
				if err := output.ExportFile(reports[0], exportFlag); err != nil {
					return err
				}
			}
		} else {
			// Multiple reports — combined output
			for _, rpt := range reports {
				if err := renderOutput(rpt, baseCfg.OutputFormat); err != nil {
					return err
				}
			}
			if exportFlag != "" {
				rptPtrs := make([]*reportpkg.Report, len(reports))
				copy(rptPtrs, reports)
				if err := output.ExportMultiFile(rptPtrs, exportFlag); err != nil {
					return err
				}
			}
		}
	}

	// Legacy --json-file support (deprecated)
	if jsonFileFlag != "" && exportFlag == "" {
		if len(reports) == 1 {
			if err := output.ExportJSON(reports[0], jsonFileFlag); err != nil {
				return err
			}
		}
	}

	// Print summary for multi-identity runs
	if len(reports) > 1 {
		mr := reportpkg.NewMultiReport(reports)
		fmt.Fprintf(os.Stderr, "\n── Summary: %d identities processed ──\n", len(mr.Reports))
		fmt.Fprintf(os.Stderr, "  RBAC assignments: %d | Directory roles: %d | Access packages: %d | Groups: %d\n",
			mr.TotalRBAC, mr.TotalDirRoles, mr.TotalPackages, mr.TotalGroups)
		if mr.TotalWarnings > 0 {
			fmt.Fprintf(os.Stderr, "  Warnings: %d\n", mr.TotalWarnings)
		}
	}

	return nil
}

// renderOutput renders a single report to stdout in the requested format.
func renderOutput(rpt *reportpkg.Report, format string) error {
	switch format {
	case "json":
		return output.PrintJSON(rpt)
	case "csv":
		f, err := output.GetFormatter("csv")
		if err != nil {
			return fmt.Errorf("failed to get CSV formatter: %w", err)
		}
		data, err := f.FormatReport(rpt)
		if err != nil {
			return fmt.Errorf("failed to format CSV: %w", err)
		}
		if _, err := os.Stdout.Write(data); err != nil {
			return fmt.Errorf("failed to write CSV output: %w", err)
		}
	case "markdown":
		f, err := output.GetFormatter("markdown")
		if err != nil {
			return fmt.Errorf("failed to get Markdown formatter: %w", err)
		}
		data, err := f.FormatReport(rpt)
		if err != nil {
			return fmt.Errorf("failed to format Markdown: %w", err)
		}
		if _, err := os.Stdout.Write(data); err != nil {
			return fmt.Errorf("failed to write Markdown output: %w", err)
		}
	case "table":
		output.PrintTable(rpt)
	default:
		return fmt.Errorf("invalid output format %q — valid values: table, json, csv, markdown", format)
	}
	return nil
}

// perIdentityFilename generates a unique export filename per identity.
func perIdentityFilename(basePath string, displayName string, index int) string {
	ext := filepath.Ext(basePath)
	base := strings.TrimSuffix(basePath, ext)
	safeName := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, displayName)
	// Truncate to avoid exceeding filesystem path length limits.
	if len(safeName) > 80 {
		safeName = safeName[:80]
	}
	return fmt.Sprintf("%s-%03d-%s%s", base, index, safeName, ext)
}
