package compare

import (
	"strings"
)

// noiseSegments contains segments to ignore during common-segment detection.
var noiseSegments = map[string]bool{
	"sub":     true,
	"spn":     true,
	"azg":     true,
	"rg":      true,
	"prod":    true,
	"dev":     true,
	"stg":     true,
	"staging": true,
	"hub":     true,
	"spoke":   true,
	"01":      true,
	"02":      true,
	"03":      true,
	"04":      true,
	"05":      true,
}

// envSegments contains environment and topology-tier segments that are
// normalized to {env} during scope comparison. This is the built-in set;
// users can extend it via --env-segments.
var envSegments = map[string]bool{
	"prod":    true,
	"dev":     true,
	"stg":     true,
	"staging": true,
	"mod":     true,
	"uat":     true,
	"qa":      true,
	"test":    true,
	"sandbox": true,
	"nonprod": true,
	"preprod": true,
	"hub":     true,
	"spoke":   true,
}

// isNoiseSegment reports whether seg should be ignored during common-segment
// detection. A segment is noise if it is in the noiseSegments set, is all
// digits, or is 1-2 characters long.
func isNoiseSegment(seg string) bool {
	if len(seg) <= 2 {
		return true
	}
	if noiseSegments[seg] {
		return true
	}
	return isAllDigits(seg)
}

// isAllDigits reports whether s is non-empty and contains only ASCII digits.
func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// normalizeNameSegments replaces known environment/topology segments with {env}
// and pure-numeric segments with {n} in a hyphen-delimited name.
// extraEnv contains additional user-defined segments to treat as {env}.
func normalizeNameSegments(name string, extraEnv map[string]bool) string {
	segments := strings.Split(name, "-")
	for i, seg := range segments {
		lower := strings.ToLower(seg)
		if envSegments[lower] || extraEnv[lower] {
			segments[i] = "{env}"
			continue
		}
		if isAllDigits(seg) {
			segments[i] = "{n}"
			continue
		}
	}
	return strings.Join(segments, "-")
}

// ExtractWorkloadName extracts the workload name from an SPN display name,
// validated against subscription names. It first tries the "wkld-" pattern,
// then falls back to longest common-segment detection.
func ExtractWorkloadName(spnName string, subNames []string) string {
	spnLower := strings.ToLower(spnName)

	// Priority 1: wkld- pattern
	if idx := strings.Index(spnLower, "wkld-"); idx >= 0 {
		after := spnLower[idx+len("wkld-"):]
		token := after
		if dash := strings.Index(after, "-"); dash >= 0 {
			token = after[:dash]
		}
		if token != "" {
			for _, sub := range subNames {
				if strings.Contains(strings.ToLower(sub), token) {
					return token
				}
			}
		}
	}

	// Priority 2: common-segment detection
	spnSegments := strings.Split(spnLower, "-")
	var candidates []string
	for _, seg := range spnSegments {
		if isNoiseSegment(seg) {
			continue
		}
		candidates = append(candidates, seg)
	}

	var best string
	for _, candidate := range candidates {
		for _, sub := range subNames {
			subSegments := strings.Split(strings.ToLower(sub), "-")
			for _, sseg := range subSegments {
				if sseg == candidate && len(candidate) > len(best) {
					best = candidate
				}
			}
		}
	}
	return best
}

// NormalizeScope normalizes an ARM scope path by replacing the workload name
// with {workload}, known environment/topology segments with {env}, and numeric
// segments with {n}. extraEnv contains additional user-defined environment
// segments. It returns a simplified path of the form:
//
//	normalizedSubName[/normalizedRGName[/resourceType/normalizedResourceName]]
func NormalizeScope(scope string, workloadName string, subNames map[string]string, extraEnv map[string]bool) string {
	if !strings.Contains(strings.ToLower(scope), "/subscriptions/") {
		return scope
	}

	parts := strings.Split(scope, "/")

	// Find subscription GUID
	var subGUID string
	for i, p := range parts {
		if strings.EqualFold(p, "subscriptions") && i+1 < len(parts) {
			subGUID = parts[i+1]
			break
		}
	}

	// Look up and normalize sub display name
	subDisplayName := subNames[subGUID]
	normalizedSub := subDisplayName
	if workloadName != "" && subDisplayName != "" {
		normalizedSub = replaceInsensitive(subDisplayName, workloadName, "{workload}")
	}
	normalizedSub = normalizeNameSegments(normalizedSub, extraEnv)

	// Find resource group name
	var rgName string
	var rgIdx int
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			rgName = parts[i+1]
			rgIdx = i + 1
			break
		}
	}

	if rgName == "" {
		// Subscription-level scope
		return normalizedSub
	}

	normalizedRG := rgName
	if workloadName != "" {
		normalizedRG = replaceInsensitive(rgName, workloadName, "{workload}")
	}
	normalizedRG = normalizeNameSegments(normalizedRG, extraEnv)

	// Check for resource-level scope (segments after the RG)
	remaining := parts[rgIdx+1:]
	if len(remaining) >= 3 && strings.EqualFold(remaining[0], "providers") {
		// remaining: ["providers", "Microsoft.X", "resourceType", "resourceName", ...]
		// Build resourceType from provider segments and normalize the resource name
		if len(remaining) >= 4 {
			resourceType := remaining[1] + "/" + remaining[2]
			resourceName := remaining[3]
			normalizedRes := resourceName
			if workloadName != "" {
				normalizedRes = replaceInsensitive(resourceName, workloadName, "{workload}")
			}
			normalizedRes = normalizeNameSegments(normalizedRes, extraEnv)
			return normalizedSub + "/" + normalizedRG + "/" + resourceType + "/" + normalizedRes
		}
	}

	// RG-level scope
	return normalizedSub + "/" + normalizedRG
}

// WorkloadScopeKey returns a combined key of role name and normalized scope.
func WorkloadScopeKey(roleName, normalizedScope string) string {
	return roleName + "|" + normalizedScope
}

// replaceInsensitive replaces all case-insensitive occurrences of old with new
// in s, preserving surrounding text.
func replaceInsensitive(s, old, replacement string) string {
	lower := strings.ToLower(s)
	oldLower := strings.ToLower(old)
	var b strings.Builder
	start := 0
	for {
		idx := strings.Index(lower[start:], oldLower)
		if idx < 0 {
			b.WriteString(s[start:])
			break
		}
		b.WriteString(s[start : start+idx])
		b.WriteString(replacement)
		start += idx + len(old)
	}
	return b.String()
}
