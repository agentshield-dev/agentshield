package istio

import (
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

const collectionResourceCoverage = kubernetesplugin.CollectionResourceCoverage

type coverageRecord = kubernetesplugin.ResourceCoverage

func coverageHealth(records map[string]coverageRecord) (string, bool) {
	byCapability := make(map[string]kubernetesplugin.CoverageStatus, len(records))
	for _, record := range records {
		status, exists := byCapability[record.Capability]
		if !exists || status == kubernetesplugin.CoverageCovered {
			byCapability[record.Capability] = record.Status
		}
	}
	health := "healthy"
	for _, capability := range []string{"istio-security-v1", "istio-networking-v1"} {
		if byCapability[capability] != kubernetesplugin.CoverageCovered {
			health = "degraded"
		}
	}
	for _, record := range records {
		if record.Required && record.Status != kubernetesplugin.CoverageCovered {
			health = "degraded"
		}
		if record.Status == kubernetesplugin.CoverageDegraded || record.Status == kubernetesplugin.CoverageFailed {
			health = "degraded"
		}
	}
	return health, byCapability["istio-gateway-v1"] == kubernetesplugin.CoverageCovered
}
