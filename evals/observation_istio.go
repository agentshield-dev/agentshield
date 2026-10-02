package evals

import (
	"context"
	"fmt"
	"strings"
)

const defaultObservationAdapterID = "istio-otlp"

type istioOTLPObservationAdapter struct{}

func (istioOTLPObservationAdapter) ID() string {
	return "istio-otlp"
}

func (istioOTLPObservationAdapter) WaitReady(ctx context.Context, kubeconfig string, workload WorkloadContract) error {
	if err := kubectl(ctx, kubeconfig, nil, "-n", workload.Namespace, "wait", "--for=condition=Programmed", "gateway/waypoint", "--timeout=180s"); err != nil {
		return err
	}
	return kubectl(ctx, kubeconfig, nil, "-n", workload.Namespace, "wait", "--for=condition=Available", "deployment/waypoint", "--timeout=180s")
}

func (istioOTLPObservationAdapter) Manifest(_ Campaign, workload WorkloadContract) string {
	return strings.Join([]string{
		fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    istio.io/dataplane-mode: ambient
    istio.io/use-waypoint: waypoint
    %s: %s`, workload.Namespace, evalLabel, workload.RuntimeID),
		fmt.Sprintf(`apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: waypoint
  namespace: %s
  labels:
    istio.io/waypoint-for: all
    %s: %s
spec:
  gatewayClassName: istio-waypoint
  listeners:
  - {name: mesh, port: 15008, protocol: HBONE}`, workload.Namespace, evalLabel, workload.RuntimeID),
		istioTelemetry(workload.Namespace, workload.RuntimeID),
	}, "\n---\n")
}

func istioTelemetry(namespace, campaign string) string {
	return fmt.Sprintf(`apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  name: waypoint-access-logs
  namespace: %s
  labels: {%s: %s}
spec:
  targetRefs:
  - {group: gateway.networking.k8s.io, kind: Gateway, name: waypoint}
  accessLogging:
  - providers:
    - {name: agentshield-otel}`, namespace, evalLabel, campaign)
}
