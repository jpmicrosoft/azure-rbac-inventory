package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

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
	printRBACAssignments(rpt.RBACAssignments)
	printDirectoryRoles(rpt.DirectoryRoles)
	printAccessPackages(rpt.AccessPackages)
	printAccessRequests(rpt.AccessRequests)
	printGroupMemberships(rpt.GroupMemberships)
	printWarnings(rpt.Warnings)
}

// PrintJSON renders the report as JSON to stdout.
func PrintJSON(rpt *reportpkg.Report) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rpt)
}

// ExportJSON writes the report to a JSON file.
func ExportJSON(rpt *reportpkg.Report, filePath string) error {
	data, err := json.MarshalIndent(rpt, "", "  ")
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
	fmt.Printf("    Name:       %s\n", rpt.Identity.DisplayName)
	fmt.Printf("    Object ID:  %s\n", rpt.Identity.ObjectID)
	fmt.Printf("    Type:       %s\n", string(rpt.Identity.Type))
	if rpt.Identity.AppID != "" {
		fmt.Printf("    App ID:     %s\n", rpt.Identity.AppID)
	}
	if rpt.Identity.ServicePrincipalType != "" {
		fmt.Printf("    SPN Type:   %s\n", rpt.Identity.ServicePrincipalType)
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
	parts := strings.Split(strings.TrimRight(scope, "/"), "/")

	switch scopeType {
	case "Management Group":
		for i, p := range parts {
			if p == "managementGroups" && i+1 < len(parts) {
				return "Management Group: " + parts[i+1], ""
			}
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

// rbacGroupItem holds a single assignment within a resource-type group.
type rbacGroupItem struct {
	roleName       string
	resourceName   string
	assignmentType string
}

func printRBACAssignments(assignments []rbac.RoleAssignment) {
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
		gName, resName := extractResourceInfo(a.Scope, a.ScopeType)

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
		fmt.Printf("\n    ► %s (%d)\n", g.name, len(g.items))

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
				fmt.Fprintf(w, "        %s\t→ %s\t%s\n", item.roleName, item.resourceName, item.assignmentType)
			}
			w.Flush()
		} else {
			for _, item := range g.items {
				fmt.Printf("        %-40s [%s]\n", item.roleName, item.assignmentType)
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
		fmt.Printf("    * %s  [%s]\n", r.RoleName, r.Status)
	}
	fmt.Println()
}

func printAccessPackages(packages []graph.AccessPackageAssignment) {
	fmt.Printf("  [PACKAGES] Access Package Assignments (%d)\n", len(packages))
	fmt.Println("  " + strings.Repeat("-", 54))

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
		fmt.Fprintf(w, "    %s\t%s\t%s\t%s\n", p.PackageName, p.CatalogName, p.Status, expires)
	}
	w.Flush()
	fmt.Println()
}

func printAccessRequests(requests []graph.AccessPackageRequest) {
	fmt.Printf("  [REQUESTS] Access Package Requests (%d)\n", len(requests))
	fmt.Println("  " + strings.Repeat("-", 54))

	if len(requests) == 0 {
		fmt.Println("    None found.")
		fmt.Println()
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "    PACKAGE\tTYPE\tSTATUS\tCREATED")
	fmt.Fprintln(w, "    "+strings.Repeat("-", 25)+"\t"+strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 20))
	for _, r := range requests {
		fmt.Fprintf(w, "    %s\t%s\t%s\t%s\n", r.PackageName, r.RequestType, r.Status, r.CreatedDate)
	}
	w.Flush()
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
		fmt.Fprintf(w, "    %s\t%s\t%s\n", g.GroupName, g.GroupType, g.Membership)
	}
	w.Flush()
	fmt.Println()
}

func printWarnings(warnings []string) {
	if len(warnings) == 0 {
		return
	}
	fmt.Printf("  [!] Warnings (%d)\n", len(warnings))
	fmt.Println("  " + strings.Repeat("-", 54))
	for _, w := range warnings {
		fmt.Printf("    ! %s\n", w)
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
