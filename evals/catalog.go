package evals

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

const CatalogSchemaVersion = "agentshield.mission-evals/v1alpha1"

type Catalog struct {
	SchemaVersion string     `json:"schemaVersion"`
	Mission       string     `json:"mission"`
	Campaigns     []Campaign `json:"campaigns"`
}

type Campaign struct {
	ID                   string   `json:"id"`
	Class                string   `json:"class"`
	ThreatModel          string   `json:"threatModel"`
	CompromiseAssumption string   `json:"compromiseAssumption"`
	SourceComponent      string   `json:"sourceComponent"`
	BaselineTarget       string   `json:"baselineTarget"`
	BaselineRequest      Request  `json:"baselineRequest"`
	ObservedTarget       string   `json:"observedTarget"`
	ObservedRequest      Request  `json:"observedRequest"`
	Governed             bool     `json:"governed"`
	Expected             Expected `json:"expected"`
}

type Request struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type Expected struct {
	Decision            string   `json:"decision"`
	Categories          []string `json:"categories"`
	EarliestPhase       string   `json:"earliestPhase"`
	RequiredObservation bool     `json:"requiredObservation"`
}

func LoadCatalog(path string) (Catalog, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return Catalog{}, err
	}
	var catalog Catalog
	if err := json.Unmarshal(payload, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("decode eval catalog: %w", err)
	}
	if err := catalog.Validate(); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

func (catalog Catalog) Validate() error {
	if catalog.SchemaVersion != CatalogSchemaVersion || strings.TrimSpace(catalog.Mission) == "" {
		return fmt.Errorf("unsupported eval catalog %q", catalog.SchemaVersion)
	}
	if len(catalog.Campaigns) < 4 {
		return errors.New("mission eval catalog requires at least four campaigns")
	}
	seen := make(map[string]struct{}, len(catalog.Campaigns))
	classes := make(map[string]int)
	threats := make(map[string]struct{})
	for _, campaign := range catalog.Campaigns {
		if campaign.ID == "" || campaign.ThreatModel == "" || campaign.CompromiseAssumption == "" {
			return errors.New("every campaign requires identity, threat model, and compromise assumption")
		}
		if _, ok := seen[campaign.ID]; ok {
			return fmt.Errorf("duplicate campaign %q", campaign.ID)
		}
		seen[campaign.ID] = struct{}{}
		if !slices.Contains([]string{"security", "benign"}, campaign.Class) {
			return fmt.Errorf("campaign %s has unsupported class %q", campaign.ID, campaign.Class)
		}
		if !slices.Contains([]string{"candidate_finding", "no_finding"}, campaign.Expected.Decision) || !campaign.Expected.RequiredObservation {
			return fmt.Errorf("campaign %s requires a decision and live observation contract", campaign.ID)
		}
		if campaign.SourceComponent == "" || campaign.BaselineTarget == "" || campaign.ObservedTarget == "" || campaign.Expected.EarliestPhase != "observed" {
			return fmt.Errorf("campaign %s has an incomplete longitudinal contract", campaign.ID)
		}
		for _, phase := range []struct {
			name    string
			request Request
		}{{"baseline", campaign.BaselineRequest}, {"observed", campaign.ObservedRequest}} {
			if phase.request.Method == "" || phase.request.Method != strings.ToUpper(phase.request.Method) || !strings.HasPrefix(phase.request.Path, "/") {
				return fmt.Errorf("campaign %s has an invalid %s request", campaign.ID, phase.name)
			}
		}
		classes[campaign.Class]++
		threats[campaign.ThreatModel] = struct{}{}
	}
	if classes["security"] == 0 || classes["benign"] == 0 || len(threats) < 3 {
		return errors.New("mission evals require security and benign controls across all three threat models")
	}
	return nil
}
