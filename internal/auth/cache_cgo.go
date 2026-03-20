//go:build cgo

package auth

import (
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"
)

// newCache creates a persistent token cache using the platform keychain.
// Falls back to an empty cache on error.
func newCache() azidentity.Cache {
	c, err := cache.New(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: token cache unavailable (%v), tokens will not be persisted\n", err)
		return azidentity.Cache{}
	}
	return c
}
