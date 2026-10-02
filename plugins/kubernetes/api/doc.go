// Package api decodes Kubernetes objects from their unstructured transport
// form into typed values for projection. Core and networking kinds use the
// upstream k8s.io/api types; Gateway API kinds use local subsets that decode
// only the fields projection interprets.
package api
