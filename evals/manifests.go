package evals

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

const evalLabel = "eval.agentshield.io/campaign"

type WorkloadContract struct {
	Namespace      string
	RuntimeID      string
	Manifest       string
	Source         string
	BaselineTarget string
	ObservedTarget string
}

func RenderCampaign(campaign Campaign) WorkloadContract {
	runtimeID := campaignRuntimeID(campaign.ID)
	namespace := "aseval-" + runtimeID
	source := campaign.SourceComponent
	baselineTarget := campaign.BaselineTarget
	observedTarget := campaign.ObservedTarget
	documents := []string{
		fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    %s: %s`, namespace, evalLabel, runtimeID),
		serviceAccount(namespace, runtimeID, source),
		clientDeployment(namespace, runtimeID, source),
		serviceAccount(namespace, runtimeID, baselineTarget),
		serverDeployment(namespace, runtimeID, baselineTarget),
		service(namespace, runtimeID, baselineTarget),
		serviceAccount(namespace, runtimeID, observedTarget),
		serverDeployment(namespace, runtimeID, observedTarget),
		service(namespace, runtimeID, observedTarget),
	}
	if campaign.Governed {
		documents = append(documents, networkPolicy(namespace, runtimeID, source, observedTarget))
	}
	return WorkloadContract{Namespace: namespace, RuntimeID: runtimeID, Manifest: strings.Join(documents, "\n---\n"), Source: source, BaselineTarget: baselineTarget, ObservedTarget: observedTarget}
}

func campaignRuntimeID(id string) string {
	digest := sha256.Sum256([]byte(id))
	return fmt.Sprintf("case-%x", digest[:6])
}

func serviceAccount(namespace, campaign, name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
%s`, metadata(namespace, campaign, name))
}

func metadata(namespace, campaign, name string) string {
	return fmt.Sprintf(`metadata:
  name: %s
  namespace: %s
  labels:
    app: %s
    app.kubernetes.io/name: %s
    %s: %s`, name, namespace, name, name, evalLabel, campaign)
}

func clientDeployment(namespace, campaign, name string) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
%s
spec:
  replicas: 1
  selector:
    matchLabels: {app: %s}
  template:
    metadata:
      labels: {app: %s, app.kubernetes.io/name: %s, %s: %s}
    spec:
      serviceAccountName: %s
      automountServiceAccountToken: false
      containers:
      - name: client
        image: curlimages/curl:8.12.1
        command: ["sleep", "3600"]`, metadata(namespace, campaign, name), name, name, name, evalLabel, campaign, name)
}

func serverDeployment(namespace, campaign, name string) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
%s
spec:
  replicas: 1
  selector:
    matchLabels: {app: %s}
  template:
    metadata:
      labels: {app: %s, app.kubernetes.io/name: %s, %s: %s}
    spec:
      serviceAccountName: %s
      automountServiceAccountToken: false
      containers:
      - name: server
        image: registry.k8s.io/e2e-test-images/agnhost:2.53
        args: ["netexec", "--http-port=8080", "--http-override=/echo?msg=%s"]`, metadata(namespace, campaign, name), name, name, name, evalLabel, campaign, name, name)
}

func service(namespace, campaign, name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Service
%s
spec:
  selector: {app: %s}
  ports:
  - {name: http, port: 8080, targetPort: 8080}`, metadata(namespace, campaign, name), name)
}

func networkPolicy(namespace, campaign, source, target string) string {
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: declared-observed-path
  namespace: %s
  labels: {%s: %s}
spec:
  podSelector:
    matchLabels: {app: %s}
  policyTypes: [Ingress]
  ingress:
  - from:
    - podSelector:
        matchLabels: {app: %s}
    ports:
    - {protocol: TCP, port: 8080}
  - from:
    - podSelector:
        matchLabels: {gateway.networking.k8s.io/gateway-name: waypoint}
    ports:
    - {protocol: TCP, port: 15008}`, namespace, evalLabel, campaign, target, source)
}
