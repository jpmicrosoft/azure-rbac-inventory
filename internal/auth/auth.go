package auth

import (
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"
	cloudenv "github.com/jpmicrosoft/azure-rbac-inventory/internal/cloud"
)

// ValidAuthMethods lists the supported authentication method names.
var ValidAuthMethods = []string{"default", "cli", "interactive", "device-code", "env", "managed-identity"}

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
	case "cli":
		opts := &azidentity.AzureCLICredentialOptions{}
		if tenantID != "" {
			opts.TenantID = tenantID
		}
		return azidentity.NewAzureCLICredential(opts)

	case "interactive":
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

	case "env":
		opts := &azidentity.EnvironmentCredentialOptions{}
		opts.ClientOptions.Cloud = env.CloudConfig
		return azidentity.NewEnvironmentCredential(opts)

	case "managed-identity":
		opts := &azidentity.ManagedIdentityCredentialOptions{}
		opts.ClientOptions.Cloud = env.CloudConfig
		return azidentity.NewManagedIdentityCredential(opts)

	case "default", "":
		opts := &azidentity.DefaultAzureCredentialOptions{}
		if tenantID != "" {
			opts.TenantID = tenantID
		}
		opts.ClientOptions.Cloud = env.CloudConfig
		return azidentity.NewDefaultAzureCredential(opts)

	default:
		return nil, fmt.Errorf("unknown auth method %q — valid values: %v", authMethod, ValidAuthMethods)
	}
}
