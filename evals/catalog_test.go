package evals

import "testing"

func TestMissionCatalogHasPairedLongitudinalThreatModels(t *testing.T) {
	catalog, err := LoadCatalog("campaigns.json")
	if err != nil {
		t.Fatal(err)
	}
	classes := make(map[string]map[string]bool)
	for _, campaign := range catalog.Campaigns {
		if classes[campaign.ThreatModel] == nil {
			classes[campaign.ThreatModel] = make(map[string]bool)
		}
		classes[campaign.ThreatModel][campaign.Class] = true
	}
	for threat, paired := range classes {
		if !paired["security"] || !paired["benign"] {
			t.Fatalf("threat model %s is not paired: %#v", threat, paired)
		}
	}
}
