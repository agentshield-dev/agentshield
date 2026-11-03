package graph

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	ResourceAuthoringContextAttribute   = "agentshield/resource-authoring-context"
	ResourceAuthoringProjectionMaxBytes = 40 << 10
	ResourceAuthoringAttributesMaxItems = 128
)

type ResourceAuthoringProjection struct {
	SchemaVersion string            `json:"schemaVersion"`
	Context       json.RawMessage   `json:"context"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

func NewResourceAuthoringProjection(context any, attributes map[string]string) (ResourceAuthoringProjection, error) {
	encoded, err := json.Marshal(context)
	if err != nil {
		return ResourceAuthoringProjection{}, fmt.Errorf("encode resource authoring context: %w", err)
	}
	projection := ResourceAuthoringProjection{SchemaVersion: "v1", Context: encoded, Attributes: attributes}
	if err := projection.normalize(); err != nil {
		return ResourceAuthoringProjection{}, err
	}
	return projection, nil
}

func DecodeResourceAuthoringProjection(encoded string) (ResourceAuthoringProjection, error) {
	if len(encoded) == 0 || len(encoded) > ResourceAuthoringProjectionMaxBytes {
		return ResourceAuthoringProjection{}, fmt.Errorf("resource authoring projection must contain 1-%d bytes", ResourceAuthoringProjectionMaxBytes)
	}
	var projection ResourceAuthoringProjection
	decoder := json.NewDecoder(bytes.NewBufferString(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&projection); err != nil {
		return ResourceAuthoringProjection{}, fmt.Errorf("decode resource authoring projection: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ResourceAuthoringProjection{}, errors.New("resource authoring projection must contain one JSON document")
	}
	if err := projection.normalize(); err != nil {
		return ResourceAuthoringProjection{}, err
	}
	return projection, nil
}

func (projection ResourceAuthoringProjection) Validate() error {
	return projection.normalize()
}

func (projection *ResourceAuthoringProjection) normalize() error {
	if projection.SchemaVersion != "v1" {
		return fmt.Errorf("unsupported resource authoring projection schema %q", projection.SchemaVersion)
	}
	var context map[string]any
	if len(projection.Context) == 0 || json.Unmarshal(projection.Context, &context) != nil || context == nil {
		return errors.New("resource authoring context must be a JSON object")
	}
	canonical, err := json.Marshal(context)
	if err != nil {
		return fmt.Errorf("canonicalize resource authoring context: %w", err)
	}
	projection.Context = canonical
	if len(projection.Attributes) > ResourceAuthoringAttributesMaxItems {
		return fmt.Errorf("resource authoring attributes exceed %d items", ResourceAuthoringAttributesMaxItems)
	}
	for key, value := range projection.Attributes {
		if key == "" || len(key) > 128 || len(value) > 2048 {
			return errors.New("resource authoring attribute exceeds field limits")
		}
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		return fmt.Errorf("encode resource authoring projection: %w", err)
	}
	if len(encoded) > ResourceAuthoringProjectionMaxBytes {
		return fmt.Errorf("resource authoring projection exceeds %d bytes", ResourceAuthoringProjectionMaxBytes)
	}
	return nil
}

func (projection ResourceAuthoringProjection) RevisionSHA256() (string, error) {
	if err := projection.normalize(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
