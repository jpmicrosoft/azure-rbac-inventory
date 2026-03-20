// Package auth provides Azure authentication credential management.
package auth

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"
	cloudenv "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
)

// ValidAuthMethods lists the supported authentication method names.
var ValidAuthMethods = []string{"interactive", "device-code", "environment", "managed-identity", "azurecli"}

// IsNonInteractive returns true for auth methods that do not require user interaction.
func IsNonInteractive(method string) bool {
	switch method {
	case "environment", "managed-identity", "azurecli":
		return true
	default:
		return false
	}
}

// newCache creates a persistent token cache, falling back to an empty cache on error.
func newCache() azidentity.Cache {
	c, err := cache.New(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: token cache unavailable (%v), tokens will not be persisted\n", err)
		return azidentity.Cache{}
	}
	return c
}

// GetCredential returns an azcore.TokenCredential for the given auth method and cloud.
func GetCredential(env cloudenv.Environment, tenantID string, authMethod string) (azcore.TokenCredential, error) {
	switch authMethod {
	case "interactive", "":
		opts := &azidentity.InteractiveBrowserCredentialOptions{}
		if tenantID != "" {
			opts.TenantID = tenantID
		}
		opts.ClientOptions.Cloud = env.CloudConfig
		opts.Cache = newCache()
		return azidentity.NewInteractiveBrowserCredential(opts)

	case "device-code":
		opts := &azidentity.DeviceCodeCredentialOptions{}
		if tenantID != "" {
			opts.TenantID = tenantID
		}
		opts.ClientOptions.Cloud = env.CloudConfig
		opts.Cache = newCache()
		return azidentity.NewDeviceCodeCredential(opts)

	case "environment":
		opts := &azidentity.EnvironmentCredentialOptions{}
		opts.ClientOptions.Cloud = env.CloudConfig
		return azidentity.NewEnvironmentCredential(opts)

	case "managed-identity":
		opts := &azidentity.ManagedIdentityCredentialOptions{}
		opts.ClientOptions.Cloud = env.CloudConfig
		if clientID := os.Getenv("AZURE_CLIENT_ID"); clientID != "" {
			opts.ID = azidentity.ClientID(clientID)
		}
		return azidentity.NewManagedIdentityCredential(opts)

	case "azurecli":
		opts := &azidentity.AzureCLICredentialOptions{}
		if tenantID != "" {
			opts.TenantID = tenantID
		}
		return azidentity.NewAzureCLICredential(opts)

	default:
		return nil, fmt.Errorf("unknown auth method %q — valid values: %v", authMethod, ValidAuthMethods)
	}
}

// PreAuthenticate acquires tokens for both Graph and ARM scopes sequentially.
// This prevents double browser prompts when concurrent goroutines later request
// tokens for different scopes simultaneously.
func PreAuthenticate(ctx context.Context, cred azcore.TokenCredential, env cloudenv.Environment) error {
	fmt.Fprint(os.Stderr, "Acquiring Graph API token... ")
	_, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{env.GraphScope},
	})
	if err != nil {
		return fmt.Errorf("failed to acquire Graph token: %w", err)
	}
	fmt.Fprintln(os.Stderr, "OK")

	fmt.Fprint(os.Stderr, "Acquiring ARM API token... ")
	_, err = cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{env.ARMScope},
	})
	if err != nil {
		return fmt.Errorf("failed to acquire ARM token: %w", err)
	}
	fmt.Fprintln(os.Stderr, "OK")

	return nil
}
