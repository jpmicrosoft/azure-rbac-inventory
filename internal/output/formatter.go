package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
	reportpkg "github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// knownResourceTypes maps ARM resource type segments to friendly display names.
var knownResourceTypes = map[string]string{
	"privateDnsZones":         "Private DNS Zones",
	"storageAccounts":         "Storage Accounts",
	"vaults":                  "Key Vaults",
	"virtualMachines":         "Virtual Machines",
	"containers":              "Storage Containers",
	"managedClusters":         "AKS Clusters",
	"sites":                   "App Services",
	"virtualNetworks":         "Virtual Networks",
	"networkSecurityGroups":   "Network Security Groups",
	"publicIPAddresses":       "Public IP Addresses",
	"registries":              "Container Registries",
	"workspaces":              "Workspaces",
	"keys":                    "Key Vault Keys",
	"secrets":                 "Key Vault Secrets",
	"certificates":            "Key Vault Certificates",
	"subnets":                 "Subnets",
	"firewalls":               "Firewalls",
	"privateEndpoints":        "Private Endpoints",
	"disks":                   "Managed Disks",
	"networkInterfaces":       "Network Interfaces",
	"loadBalancers":           "Load Balancers",
	"applicationGateways":     "Application Gateways",
	"routeTables":             "Route Tables",
	"natGateways":             "NAT Gateways",
	"dnsZones":                "DNS Zones",
	"virtualNetworkGateways":  "VPN Gateways",
	"bastionHosts":            "Bastion Hosts",
	"availabilitySets":        "Availability Sets",
	"virtualMachineScaleSets": "VM Scale Sets",
	"serverFarms":             "App Service Plans",
	"servers":                 "Database Servers",
	"databases":               "Databases",
	"namespaces":              "Event/Service Bus Namespaces",
	"components":              "Application Insights",
	"actionGroups":            "Action Groups",
	"accounts":                "Accounts",
	"configurationStores":     "App Configuration Stores",
	"managedEnvironments":     "Container App Environments",
	"containerApps":           "Container Apps",
	"flexibleServers":         "Flexible Servers",
	"privateLinkServices":     "Private Link Services",
	"virtualNetworkLinks":     "Virtual Network Links",
	"blobServices":            "Blob Services",
	"fileServices":            "File Services",
	"queueServices":           "Queue Services",
	"tableServices":           "Table Services",
}

// PrintTable renders the report as formatted console tables.
func PrintTable(rpt *reportpkg.Report) {
	printHeader(rpt)
	names := rpt.ManagementGroupNames
	if rpt.LegacyOutput {
		names = nil
	}
	printRBACAssignmentsWithManagementGroupNames(rpt.RBACAssignments, names)
	printDirectoryRoles(rpt.DirectoryRoles)
	printAccessPackages(rpt.AccessPackages, rpt.SkippedAccessPackages)
	printAccessRequests(rpt.AccessRequests, rpt.SkippedAccessPackages)
	printGroupMemberships(rpt.GroupMemberships)
	printWarnings(rpt.Warnings)
}

// sanitizeForTerminal renders terminal controls and directional formatting
// characters visibly while preserving ordinary Unicode text.
func sanitizeForTerminal(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7F || b >= 0x80 {
			clean = false
			break
		}
	}
	if clean {
		return s
	}

	var buf strings.Builder
	buf.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size

		switch {
		case r == '\t':
			buf.WriteByte(' ')
		case r >= 0 && r <= 0x1F:
			buf.WriteRune(rune(0x2400 + r))
		case r == 0x7F:
			buf.WriteRune(0x2421)
		case r >= 0x80 && r <= 0x9F:
			fmt.Fprintf(&buf, "<0x%02X>", r)
		case r == 0x2028 || r == 0x2029 || isBidiControl(r):
			fmt.Fprintf(&buf, "<U+%04X>", r)
		default:
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// isBidiControl identifies Unicode directional formatting controls.
func isBidiControl(r rune) bool {
	switch r {
	case 0x061C,
		0x200E,
		0x200F,
		0x202A,
		0x202B,
		0x202C,
		0x202D,
		0x202E,
		0x2066,
		0x2067,
		0x2068,
		0x2069:
		return true
	}
	return false
}

// PrintJSON renders the report as JSON to stdout.
func PrintJSON(rpt *reportpkg.Report) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(reportForSerialization(rpt))
}

// ExportJSON writes the report to a JSON file.
func ExportJSON(rpt *reportpkg.Report, filePath string) error {
	data, err := json.MarshalIndent(reportForSerialization(rpt), "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	fmt.Fprintf(os.Stderr, "\nResults exported to: %s\n", filePath)
	return nil
}

func printHeader(rpt *reportpkg.Report) {
	fmt.Println()
	fmt.Println("  ======================================================")
	fmt.Println("   Azure RBAC Inventory - Identity Report")
	fmt.Println("  ======================================================")
	fmt.Println()
	fmt.Printf("    Name:       %s\n", sanitizeForTerminal(rpt.Identity.DisplayName))
	fmt.Printf("    Object ID:  %s\n", sanitizeForTerminal(rpt.Identity.ObjectID))
	fmt.Printf("    Type:       %s\n", sanitizeForTerminal(string(rpt.Identity.Type)))
	if rpt.Identity.AppID != "" {
		fmt.Printf("    App ID:     %s\n", sanitizeForTerminal(rpt.Identity.AppID))
	}
	if rpt.Identity.ServicePrincipalType != "" {
		fmt.Printf("    SPN Type:   %s\n", sanitizeForTerminal(rpt.Identity.ServicePrincipalType))
	}
	if rpt.Identity.IsMerged {
		fmt.Println("    Merged:     App Registration + Service Principal")
	}
	fmt.Printf("    Cloud:      %s\n", rpt.Cloud)
	fmt.Println()
}

// friendlyResourceType returns a human-readable name for an ARM resource type segment.
func friendlyResourceType(rawType string) string {
	if friendly, ok := knownResourceTypes[rawType]; ok {
		return friendly
	}
	// Fallback: capitalize first letter of the raw type
	runes := []rune(rawType)
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
	}
	return string(runes)
}

// extractResourceInfo derives a group name and resource name from an ARM scope path.
func extractResourceInfo(scope, scopeType string) (groupName, resourceName string) {
	return extractResourceInfoWithManagementGroupNames(scope, scopeType, nil)
}

func extractResourceInfoWithManagementGroupNames(scope, scopeType string, managementGroupNames map[string]string) (groupName, resourceName string) {
	parts := strings.Split(strings.TrimRight(scope, "/"), "/")

	switch scopeType {
	case "Management Group":
		if scopeName := managementGroupScopeName(scope, scopeType, managementGroupNames); scopeName != "" {
			return "Management Group: " + scopeName, ""
		}
		return "Management Group", ""
	case "Subscription":
		for i, p := range parts {
			if p == "subscriptions" && i+1 < len(parts) {
				return "Subscription: " + parts[i+1], ""
			}
		}
		return "Subscription", ""
	case "Resource Group":
		for i, p := range parts {
			if p == "resourceGroups" && i+1 < len(parts) {
				return "Resource Group: " + parts[i+1], ""
			}
		}
		return "Resource Group", ""
	case "Resource":
		// Find the last "providers" segment and walk type/name pairs
		lastProviderIdx := -1
		for i, p := range parts {
			if p == "providers" {
				lastProviderIdx = i
			}
		}
		if lastProviderIdx >= 0 && lastProviderIdx+2 < len(parts) {
			// After "providers": namespace, then type/name pairs
			remaining := parts[lastProviderIdx+2:] // skip "providers" and namespace
			var deepType, deepName string
			for i := 0; i+1 < len(remaining); i += 2 {
				deepType = remaining[i]
				deepName = remaining[i+1]
			}
			if deepType != "" {
				return friendlyResourceType(deepType), deepName
			}
		}
		return "Resource", ""
	}

	return "Other", ""
}

func managementGroupScopeName(scope, scopeType string, names map[string]string) string {
	if scopeType != "Management Group" {
		return ""
	}
	parts := strings.Split(strings.TrimRight(scope, "/"), "/")
	for i, part := range parts {
		if part == "managementGroups" && i+1 < len(parts) {
			return managementGroupDisplayName(parts[i+1], names)
		}
	}
	return ""
}

func managementGroupDisplayName(id string, names map[string]string) string {
	displayName, ok := names[id]
	if !ok {
		for candidateID, candidateName := range names {
			if strings.EqualFold(candidateID, id) {
				displayName = candidateName
				ok = true
				break
			}
		}
	}
	if !ok || displayName == "" || strings.EqualFold(displayName, id) {
		return id
	}
	return fmt.Sprintf("%s (%s)", displayName, id)
}

// rbacGroupItem holds a single assignment within a resource-type group.
type rbacGroupItem struct {
	roleName       string
	resourceName   string
	assignmentType string
}

func printRBACAssignments(assignments []rbac.RoleAssignment) {
	printRBACAssignmentsWithManagementGroupNames(assignments, nil)
}

func printRBACAssignmentsWithManagementGroupNames(assignments []rbac.RoleAssignment, managementGroupNames map[string]string) {
	fmt.Printf("  [RBAC] Azure Role Assignments (%d)\n", len(assignments))
	fmt.Println("  " + strings.Repeat("-", 54))

	if len(assignments) == 0 {
		fmt.Println("    None found.")
		fmt.Println()
		return
	}

	type groupEntry struct {
		name     string
		priority int
		items    []rbacGroupItem
	}

	groupOrder := []string{}
	groups := map[string]*groupEntry{}

	for _, a := range assignments {
		gName, resName := extractResourceInfoWithManagementGroupNames(a.Scope, a.ScopeType, managementGroupNames)

		var priority int
		switch a.ScopeType {
		case "Management Group":
			priority = 0
		case "Subscription":
			priority = 1
		case "Resource Group":
			priority = 2
		default:
			priority = 3
		}

		if _, ok := groups[gName]; !ok {
			groups[gName] = &groupEntry{name: gName, priority: priority}
			groupOrder = append(groupOrder, gName)
		}
		groups[gName].items = append(groups[gName].items, rbacGroupItem{
			roleName:       a.RoleName,
			resourceName:   resName,
			assignmentType: a.AssignmentType,
		})
	}

	sort.SliceStable(groupOrder, func(i, j int) bool {
		gi, gj := groups[groupOrder[i]], groups[groupOrder[j]]
		if gi.priority != gj.priority {
			return gi.priority < gj.priority
		}
		return gi.name < gj.name
	})

	for _, key := range groupOrder {
		g := groups[key]
		fmt.Printf("\n    ► %s (%d)\n", sanitizeForTerminal(g.name), len(g.items))

		hasResourceNames := false
		for _, item := range g.items {
			if item.resourceName != "" {
				hasResourceNames = true
				break
			}
		}

		if hasResourceNames {
			w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
			for _, item := range g.items {
				fmt.Fprintf(w, "        %s\t→ %s\t%s\n", sanitizeForTerminal(item.roleName), sanitizeForTerminal(item.resourceName), sanitizeForTerminal(item.assignmentType))
			}
			_ = w.Flush()
		} else {
			for _, item := range g.items {
				fmt.Printf("        %-40s [%s]\n", sanitizeForTerminal(item.roleName), sanitizeForTerminal(item.assignmentType))
			}
		}
	}
	fmt.Println()
}

func printDirectoryRoles(roles []graph.DirectoryRole) {
	fmt.Printf("  [ROLES] Entra ID Directory Roles (%d)\n", len(roles))
	fmt.Println("  " + strings.Repeat("-", 54))

	if len(roles) == 0 {
		fmt.Println("    None found.")
		fmt.Println()
		return
	}

	for _, r := range roles {
		fmt.Printf("    * %s  [%s]\n", sanitizeForTerminal(r.RoleName), sanitizeForTerminal(r.Status))
	}
	fmt.Println()
}

func printAccessPackages(packages []graph.AccessPackageAssignment, skipped bool) {
	fmt.Printf("  [PACKAGES] Access Package Assignments (%d)\n", len(packages))
	fmt.Println("  " + strings.Repeat("-", 54))

	if skipped {
		fmt.Println("    Skipped (use --include-access-packages to query)")
		fmt.Println()
		return
	}

	if len(packages) == 0 {
		fmt.Println("    None found.")
		fmt.Println()
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "    PACKAGE\tCATALOG\tSTATUS\tEXPIRES")
	fmt.Fprintln(w, "    "+strings.Repeat("-", 25)+"\t"+strings.Repeat("-", 20)+"\t"+strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 12))
	for _, p := range packages {
		expires := p.ExpirationDate
		if expires == "" {
			expires = "-"
		}
		fmt.Fprintf(w, "    %s\t%s\t%s\t%s\n", sanitizeForTerminal(p.PackageName), sanitizeForTerminal(p.CatalogName), sanitizeForTerminal(p.Status), sanitizeForTerminal(expires))
	}
	_ = w.Flush()
	fmt.Println()
}

func printAccessRequests(requests []graph.AccessPackageRequest, skipped bool) {
	fmt.Printf("  [REQUESTS] Access Package Requests (%d)\n", len(requests))
	fmt.Println("  " + strings.Repeat("-", 54))

	if skipped {
		fmt.Println("    Skipped (use --include-access-packages to query)")
		fmt.Println()
		return
	}

	if len(requests) == 0 {
		fmt.Println("    None found.")
		fmt.Println()
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "    PACKAGE\tTYPE\tSTATUS\tCREATED")
	fmt.Fprintln(w, "    "+strings.Repeat("-", 25)+"\t"+strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 20))
	for _, r := range requests {
		fmt.Fprintf(w, "    %s\t%s\t%s\t%s\n", sanitizeForTerminal(r.PackageName), sanitizeForTerminal(r.RequestType), sanitizeForTerminal(r.Status), sanitizeForTerminal(r.CreatedDate))
	}
	_ = w.Flush()
	fmt.Println()
}

func printGroupMemberships(groups []graph.GroupMembership) {
	fmt.Printf("  [GROUPS] Group Memberships (%d)\n", len(groups))
	fmt.Println("  " + strings.Repeat("-", 54))

	if len(groups) == 0 {
		fmt.Println("    None found.")
		fmt.Println()
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "    GROUP\tTYPE\tMEMBERSHIP")
	fmt.Fprintln(w, "    "+strings.Repeat("-", 30)+"\t"+strings.Repeat("-", 15)+"\t"+strings.Repeat("-", 12))
	for _, g := range groups {
		fmt.Fprintf(w, "    %s\t%s\t%s\n", sanitizeForTerminal(g.GroupName), sanitizeForTerminal(g.GroupType), sanitizeForTerminal(g.Membership))
	}
	_ = w.Flush()
	fmt.Println()
}

func printWarnings(warnings []string) {
	if len(warnings) == 0 {
		return
	}
	fmt.Printf("  [!] Warnings (%d)\n", len(warnings))
	fmt.Println("  " + strings.Repeat("-", 54))
	for _, w := range warnings {
		fmt.Printf("    ! %s\n", sanitizeForTerminal(w))
	}
	fmt.Println()
}

// friendlyScope extracts a human-readable scope description.
func friendlyScope(scope string, scopeType string) string {
	parts := strings.Split(strings.TrimRight(scope, "/"), "/")

	switch scopeType {
	case "Management Group":
		for i, p := range parts {
			if p == "managementGroups" && i+1 < len(parts) {
				return "MG: " + parts[i+1]
			}
		}
	case "Subscription":
		for i, p := range parts {
			if p == "subscriptions" && i+1 < len(parts) {
				return "Sub: " + parts[i+1]
			}
		}
	case "Resource Group":
		for i, p := range parts {
			if p == "resourceGroups" && i+1 < len(parts) {
				return "RG: " + parts[i+1]
			}
		}
	case "Resource":
		if len(parts) >= 2 {
			return parts[len(parts)-2] + "/" + parts[len(parts)-1]
		}
	}

	return truncateScope(scope, 50)
}

func truncateScope(scope string, maxLen int) string {
	if maxLen < 4 {
		maxLen = 4
	}
	if len(scope) <= maxLen {
		return scope
	}
	return "..." + scope[len(scope)-maxLen+3:]
}
