package cloud

import (
	"strings"

	azcloud "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
)

// Environment represents an Azure cloud environment with its endpoint URLs.
type Environment struct {
	Name          string
	ARMEndpoint   string
	ARMScope      string
	GraphEndpoint string
	GraphScope    string
	LoginEndpoint string
	CloudConfig   azcloud.Configuration
}

var (
	// AzureCloud is the Azure public/commercial cloud environment.
	AzureCloud = Environment{
		Name:          "AzureCloud",
		ARMEndpoint:   "https://management.azure.com",
		ARMScope:      "https://management.azure.com/.default",
		GraphEndpoint: "https://graph.microsoft.com",
		GraphScope:    "https://graph.microsoft.com/.default",
		LoginEndpoint: "https://login.microsoftonline.com",
		CloudConfig:   azcloud.AzurePublic,
	}

	// AzureUSGovernment is the Azure US Government cloud environment.
	AzureUSGovernment = Environment{
		Name:          "AzureUSGovernment",
		ARMEndpoint:   "https://management.usgovcloudapi.net",
		ARMScope:      "https://management.usgovcloudapi.net/.default",
		GraphEndpoint: "https://graph.microsoft.us",
		GraphScope:    "https://graph.microsoft.us/.default",
		LoginEndpoint: "https://login.microsoftonline.us",
		CloudConfig:   azcloud.AzureGovernment,
	}

	// AzureChinaCloud is the Azure China (21Vianet-operated) cloud environment.
	AzureChinaCloud = Environment{
		Name:          "AzureChinaCloud",
		ARMEndpoint:   "https://management.chinacloudapi.cn",
		ARMScope:      "https://management.chinacloudapi.cn/.default",
		GraphEndpoint: "https://microsoftgraph.chinacloudapi.cn",
		GraphScope:    "https://microsoftgraph.chinacloudapi.cn/.default",
		LoginEndpoint: "https://login.chinacloudapi.cn",
		CloudConfig:   azcloud.AzureChina,
	}

	// ValidCloudNames lists all accepted --cloud values.
	ValidCloudNames = []string{"AzureCloud", "AzureUSGovernment", "AzureChinaCloud"}
)

// GetEnvironment returns the cloud environment by name (case-insensitive).
func GetEnvironment(name string) (Environment, bool) {
	switch strings.ToLower(name) {
	case "azurecloud":
		return AzureCloud, true
	case "azureusgovernment":
		return AzureUSGovernment, true
	case "azurechinacloud":
		return AzureChinaCloud, true
	default:
		return Environment{}, false
	}
}
