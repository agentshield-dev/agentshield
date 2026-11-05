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
	ResourceAuthoringContextMaxBytes    = 40 << 10
	ResourceAuthoringAttributesMaxItems = 128
)

type ResourceAuthoringContext struct {
	SchemaVersion string            `json:"schemaVersion"`
	Context       json.RawMessage   `json:"context"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

func NewResourceAuthoringContext(context any, attributes map[string]string) (ResourceAuthoringContext, error) {
	encoded, err := json.Marshal(context)
	if err != nil {
		return ResourceAuthoringContext{}, fmt.Errorf("encode resource authoring context: %w", err)
	}
	authoringContext := ResourceAuthoringContext{SchemaVersion: "v1", Context: encoded, Attributes: attributes}
	if err := authoringContext.normalize(); err != nil {
		return ResourceAuthoringContext{}, err
	}
	return authoringContext, nil
}

func DecodeResourceAuthoringContext(encoded string) (ResourceAuthoringContext, error) {
	if len(encoded) == 0 || len(encoded) > ResourceAuthoringContextMaxBytes {
		return ResourceAuthoringContext{}, fmt.Errorf("resource authoring context must contain 1-%d bytes", ResourceAuthoringContextMaxBytes)
	}
	var authoringContext ResourceAuthoringContext
	decoder := json.NewDecoder(bytes.NewBufferString(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&authoringContext); err != nil {
		return ResourceAuthoringContext{}, fmt.Errorf("decode resource authoring context: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ResourceAuthoringContext{}, errors.New("resource authoring context must contain one JSON document")
	}
	if err := authoringContext.normalize(); err != nil {
		return ResourceAuthoringContext{}, err
	}
	return authoringContext, nil
}

func (authoringContext ResourceAuthoringContext) Validate() error {
	return authoringContext.normalize()
}

func (authoringContext *ResourceAuthoringContext) normalize() error {
	if authoringContext.SchemaVersion != "v1" {
		return fmt.Errorf("unsupported resource authoring context schema %q", authoringContext.SchemaVersion)
	}
	var context map[string]any
	if len(authoringContext.Context) == 0 || json.Unmarshal(authoringContext.Context, &context) != nil || context == nil {
		return errors.New("resource authoring context must be a JSON object")
	}
	canonical, err := json.Marshal(context)
	if err != nil {
		return fmt.Errorf("canonicalize resource authoring context: %w", err)
	}
	authoringContext.Context = canonical
	if len(authoringContext.Attributes) > ResourceAuthoringAttributesMaxItems {
		return fmt.Errorf("resource authoring attributes exceed %d items", ResourceAuthoringAttributesMaxItems)
	}
	for key, value := range authoringContext.Attributes {
		if key == "" || len(key) > 128 || len(value) > 2048 {
			return errors.New("resource authoring attribute exceeds field limits")
		}
	}
	encoded, err := json.Marshal(authoringContext)
	if err != nil {
		return fmt.Errorf("encode resource authoring context: %w", err)
	}
	if len(encoded) > ResourceAuthoringContextMaxBytes {
		return fmt.Errorf("resource authoring context exceeds %d bytes", ResourceAuthoringContextMaxBytes)
	}
	return nil
}

func (authoringContext ResourceAuthoringContext) SHA256() (string, error) {
	if err := authoringContext.normalize(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(authoringContext)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
