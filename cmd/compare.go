package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/spf13/cobra"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/auth"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/checker"
	cloudenv "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/compare"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/output"
	reportpkg "github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

var modelFlag string
var workloadKeyFlag string

var compareCmd = &cobra.Command{
	Use:   "compare <identity-A> <identity-B>",
	Short: "Compare RBAC assignments between two or more identities",
	Long: `Compare RBAC assignments, directory roles, group memberships, and access
packages between identities. Supports 1:1 comparison and 1:N model comparison.

Examples:
  # Compare two identities
  azure-rbac-inventory compare <id-A> <id-B> --cloud AzureUSGovernment

  # Model compare — baseline vs multiple targets
  azure-rbac-inventory compare --model <model-id> <target-1> <target-2>
  azure-rbac-inventory compare --model <model-id> --file targets.csv

  # Export comparison to HTML
  azure-rbac-inventory compare <id-A> <id-B> --export diff.html

  # Workload-aware model compare (auto-detect workload names)
  azure-rbac-inventory compare --model spn-fedrampmod-wkld-axonius spn-fedrampmod-wkld-zscaler

  # Explicit workload key
  azure-rbac-inventory compare --model spn-fedrampmod-wkld-axonius --workload-key axonius --file targets.csv`,
	Args: func(cmd *cobra.Command, args []string) error {
		model, _ := cmd.Flags().GetString("model")
		file, _ := cmd.Flags().GetString("file")

		if model != "" {
			// Model mode: targets come from args and/or --file
			if len(args) == 0 && file == "" {
				return fmt.Errorf("model mode requires at least one target identity (positional args or --file)")
			}
			return nil
		}

		// 1:1 mode: exactly 2 positional args
		if file != "" {
			return fmt.Errorf("--file without --model is not supported; use --model for 1:N comparison")
		}
		if len(args) != 2 {
			return fmt.Errorf("requires exactly 2 identity arguments for 1:1 comparison (got %d); use --model for 1:N", len(args))
		}
		return nil
	},
	RunE: runCompare,
}

func init() {
	compareCmd.Flags().StringVar(&modelFlag, "model", "", "Model identity ID for 1:N comparison")
	compareCmd.Flags().StringVar(&workloadKeyFlag, "workload-key", "", "Explicit workload name for the golden SPN (auto-detected if omitted)")
	rootCmd.AddCommand(compareCmd)
}

func runCompare(cmd *cobra.Command, args []string) error {
	if maxResultsFlag <= 0 {
		return fmt.Errorf("--max-results must be a positive integer, got %d", maxResultsFlag)
	}
	if concurrencyFlag <= 0 || concurrencyFlag > 50 {
		return fmt.Errorf("--concurrency must be between 1 and 50, got %d", concurrencyFlag)
	}

	// Validate input lengths to prevent oversized API requests.
	const maxInputLen = 256
	if len(modelFlag) > maxInputLen {
		return fmt.Errorf("--model value exceeds maximum length of %d characters", maxInputLen)
	}
	for _, a := range args {
		if len(a) > maxInputLen {
			return fmt.Errorf("identity argument %q exceeds maximum length of %d characters", a[:50]+"...", maxInputLen)
		}
	}
	if len(workloadKeyFlag) > maxInputLen {
		return fmt.Errorf("--workload-key value exceeds maximum length of %d characters", maxInputLen)
	}

	isModelMode := modelFlag != ""

	// Collect target entries from positional args and --file.
	var targetEntries []identity.InputEntry
	for _, a := range args {
		targetEntries = append(targetEntries, identity.InputEntry{ID: a})
	}
	if fileFlag != "" {
		fileEntries, err := identity.ParseInputFile(fileFlag)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Read %d identities from file\n", len(fileEntries))
		targetEntries = append(targetEntries, fileEntries...)
	}

	// Resolve cloud environment.
	env, ok := cloudenv.GetEnvironment(cloudFlag)
	if !ok {
		return fmt.Errorf("invalid cloud name %q — valid values: %v", cloudFlag, cloudenv.ValidCloudNames)
	}
	fmt.Fprintf(os.Stderr, "Cloud: %s\n", env.Name)

	// Authenticate.
	fmt.Fprint(os.Stderr, "Authenticating... ")
	cred, err := auth.GetCredential(env, tenantFlag, authMethodFlag)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	fmt.Fprintln(os.Stderr, "OK")

	ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag)
	defer cancel()

	if auth.NeedsPreAuth(authMethodFlag) {
		if err := auth.PreAuthenticate(ctx, cred, env, authMethodFlag); err != nil {
			return fmt.Errorf("pre-authentication failed: %w", err)
		}
	}

	// Set up Graph client and resolver.
	graphClient := graph.NewClient(cred, env)
	resolver := identity.NewResolver(graphClient)

	baseCfg := checker.Config{
		Cloud:                 cloudFlag,
		TenantID:              tenantFlag,
		Subscriptions:         checker.ParseSubscriptions(subscriptionsFlag),
		IncludeGroups:         includeGroupRBACFlag,
		IncludeAccessPackages: includeAccessPackagesFlag,
		Verbose:               verboseFlag,
		OutputFormat:          outputFlag,
		IdentityType:          typeFlag,
		MaxResults:            maxResultsFlag,
		Concurrency:           concurrencyFlag,
	}

	if isModelMode {
		return runModelCompare(ctx, cred, env, resolver, baseCfg, targetEntries)
	}
	return run1to1Compare(ctx, cred, env, resolver, baseCfg, targetEntries)
}

// run1to1Compare performs a 1:1 comparison between exactly two identities.
func run1to1Compare(
	ctx context.Context,
	cred azcore.TokenCredential,
	env cloudenv.Environment,
	resolver *identity.Resolver,
	baseCfg checker.Config,
	entries []identity.InputEntry,
) error {
	// Resolve both identities.
	idA, err := resolveOneIdentity(ctx, resolver, entries[0], baseCfg)
	if err != nil {
		return fmt.Errorf("failed to resolve identity A (%s): %w", entries[0].ID, err)
	}
	idB, err := resolveOneIdentity(ctx, resolver, entries[1], baseCfg)
	if err != nil {
		return fmt.Errorf("failed to resolve identity B (%s): %w", entries[1].ID, err)
	}

	// Run checker for both.
	fmt.Fprintf(os.Stderr, "\n── Checking identity A ──\n")
	cfgA := baseCfg
	cfgA.IdentityID = idA
	reportA, err := checker.Run(ctx, cred, env, cfgA)
	if err != nil {
		return fmt.Errorf("failed to check identity A (%s): %w", idA, err)
	}

	fmt.Fprintf(os.Stderr, "\n── Checking identity B ──\n")
	cfgB := baseCfg
	cfgB.IdentityID = idB
	reportB, err := checker.Run(ctx, cred, env, cfgB)
	if err != nil {
		return fmt.Errorf("failed to check identity B (%s): %w", idB, err)
	}

	// Compare.
	result := compare.CompareReports(reportA, reportB)

	return renderCompareOutput(result, outputFlag)
}

// runModelCompare performs a 1:N model comparison.
func runModelCompare(
	ctx context.Context,
	cred azcore.TokenCredential,
	env cloudenv.Environment,
	resolver *identity.Resolver,
	baseCfg checker.Config,
	targetEntries []identity.InputEntry,
) error {
	// Resolve model identity.
	modelEntry := identity.InputEntry{ID: modelFlag}
	modelID, err := resolveOneIdentity(ctx, resolver, modelEntry, baseCfg)
	if err != nil {
		return fmt.Errorf("failed to resolve model identity (%s): %w", modelFlag, err)
	}

	// Run checker for model.
	fmt.Fprintf(os.Stderr, "\n── Checking model identity ──\n")
	modelCfg := baseCfg
	modelCfg.IdentityID = modelID
	modelReport, err := checker.Run(ctx, cred, env, modelCfg)
	if err != nil {
		return fmt.Errorf("failed to check model identity (%s): %w", modelID, err)
	}

	// Resolve all target identities.
	var targetIDs []string
	for _, entry := range targetEntries {
		ids, err := resolveIdentities(ctx, resolver, entry, baseCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to resolve %q: %v\n", entry.ID, err)
			continue
		}
		targetIDs = append(targetIDs, ids...)
	}

	if len(targetIDs) == 0 {
		return fmt.Errorf("no target identities to compare")
	}

	const maxTargets = 200
	if len(targetIDs) > maxTargets {
		return fmt.Errorf("resolved %d target identities, exceeding maximum of %d; narrow your search", len(targetIDs), maxTargets)
	}

	fmt.Fprintf(os.Stderr, "\nComparing model against %d targets...\n", len(targetIDs))

	// Run checker for each target.
	var targetReports []*reportpkg.Report
	for i, id := range targetIDs {
		fmt.Fprintf(os.Stderr, "\n── Target %d/%d ──\n", i+1, len(targetIDs))
		cfg := baseCfg
		cfg.IdentityID = id
		rpt, err := checker.Run(ctx, cred, env, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to process target %s: %v\n", id, err)
			continue
		}
		targetReports = append(targetReports, rpt)
	}

	if len(targetReports) == 0 {
		return fmt.Errorf("all target identity checks failed")
	}

	// Model compare (workload-aware).
	result := compare.WorkloadModelCompare(modelReport, targetReports, workloadKeyFlag)

	if result.GoldenWorkload != "" {
		fmt.Fprintf(os.Stderr, "Workload detected — golden: %s\n", result.GoldenWorkload)
	}
	for _, r := range result.Results {
		if r.WorkloadName != "" {
			fmt.Fprintf(os.Stderr, "  Target %s — workload: %s\n", r.Target.DisplayName, r.WorkloadName)
		}
	}

	return renderModelCompareOutput(result, outputFlag)
}

// resolveOneIdentity resolves a single input entry to exactly one identity ID.
// If the input is a pattern, it must match exactly one identity.
func resolveOneIdentity(ctx context.Context, resolver *identity.Resolver, entry identity.InputEntry, cfg checker.Config) (string, error) {
	ids, err := resolveIdentities(ctx, resolver, entry, cfg)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("no identities found for %q", entry.ID)
	}
	if len(ids) > 1 {
		return "", fmt.Errorf("pattern %q matched %d identities; expected exactly 1 for comparison — narrow your search or use an object ID", entry.ID, len(ids))
	}
	return ids[0], nil
}

// resolveIdentities resolves an input entry to one or more identity IDs.
func resolveIdentities(ctx context.Context, resolver *identity.Resolver, entry identity.InputEntry, cfg checker.Config) ([]string, error) {
	searchType := cfg.IdentityType
	if entry.Type != "" && entry.Type != "all" {
		searchType = entry.Type
	}

	if !identity.IsPattern(entry.ID) {
		return []string{entry.ID}, nil
	}

	fmt.Fprintf(os.Stderr, "Searching for identities matching: %s\n", entry.ID)
	results, err := resolver.Search(ctx, entry.ID, searchType, cfg.MaxResults)
	if err != nil {
		return nil, fmt.Errorf("search for %q failed: %w", entry.ID, err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no identities found matching %q", entry.ID)
	}

	fmt.Fprintf(os.Stderr, "  Found %d matching identities:\n", len(results))
	var ids []string
	for i, r := range results {
		appInfo := ""
		if r.Identity.AppID != "" {
			appInfo = fmt.Sprintf("  AppID: %s", r.Identity.AppID)
		}
		fmt.Fprintf(os.Stderr, "    %d. %s  (%s)  %s%s\n", i+1, r.Identity.DisplayName, r.Identity.Type, r.Identity.ObjectID, appInfo)
		ids = append(ids, r.Identity.ObjectID)
	}
	return ids, nil
}

// renderCompareOutput renders a 1:1 comparison result to stdout and optionally exports.
func renderCompareOutput(result *compare.ComparisonResult, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return err
		}
	case "table":
		output.PrintCompare(result)
	case "csv", "markdown":
		return fmt.Errorf("output format %q is not supported for compare — use table, json, or --export .html", format)
	default:
		return fmt.Errorf("invalid output format %q — valid values: table, json, csv, markdown", format)
	}

	if exportFlag != "" {
		return exportCompareResult(result, exportFlag)
	}
	return nil
}

// exportCompareResult exports the 1:1 comparison to a file.
func exportCompareResult(result *compare.ComparisonResult, path string) error {
	ext := strings.ToLower(filepath.Ext(path))
	var data []byte
	var err error

	switch ext {
	case ".html":
		data, err = output.FormatCompareHTML(result)
	case ".json":
		enc, _ := json.MarshalIndent(result, "", "  ")
		data = enc
	default:
		return fmt.Errorf("unsupported export format %q for compare — supported: .html, .json", ext)
	}
	if err != nil {
		return fmt.Errorf("formatting export: %w", err)
	}

	if err := validateExportPath(path); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing export file: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Exported comparison to %s\n", path)
	return nil
}

// renderModelCompareOutput renders a 1:N model comparison result to stdout and optionally exports.
func renderModelCompareOutput(result *compare.ModelComparisonResult, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return err
		}
	case "table":
		output.PrintModelCompare(result)
	case "csv", "markdown":
		return fmt.Errorf("output format %q is not supported for model compare — use table, json, or --export .html", format)
	default:
		return fmt.Errorf("invalid output format %q — valid values: table, json, csv, markdown", format)
	}

	if exportFlag != "" {
		return exportModelCompareResult(result, exportFlag)
	}
	return nil
}

// exportModelCompareResult exports the 1:N model comparison to a file.
func exportModelCompareResult(result *compare.ModelComparisonResult, path string) error {
	ext := strings.ToLower(filepath.Ext(path))
	var data []byte
	var err error

	switch ext {
	case ".html":
		data, err = output.FormatModelCompareHTML(result)
	case ".json":
		enc, _ := json.MarshalIndent(result, "", "  ")
		data = enc
	default:
		return fmt.Errorf("unsupported export format %q for model compare — supported: .html, .json", ext)
	}
	if err != nil {
		return fmt.Errorf("formatting export: %w", err)
	}

	if err := validateExportPath(path); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing export file: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Exported model comparison to %s\n", path)
	return nil
}

// validateExportPath checks that the export path is safe to write to.
// It rejects symlinks and ensures the parent directory exists.
func validateExportPath(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving export path: %w", err)
	}

	// Reject if the target already exists and is a symlink.
	fi, err := os.Lstat(absPath)
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("export path %q is a symlink — refusing to overwrite for safety", path)
		}
	}

	// Ensure parent directory exists and is not a symlink.
	dir := filepath.Dir(absPath)
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("export directory %q does not exist", dir)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("export directory %q is a symlink — refusing to write for safety", dir)
	}
	if !dirInfo.IsDir() {
		return fmt.Errorf("export path parent %q is not a directory", dir)
	}

	return nil
}
