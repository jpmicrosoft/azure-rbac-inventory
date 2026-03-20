//go:build !cgo

package auth

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// newCache returns an empty cache when CGO is disabled (static/cross-compiled builds).
// Token caching requires platform keychain access via CGO.
func newCache() azidentity.Cache {
	return azidentity.Cache{}
}
