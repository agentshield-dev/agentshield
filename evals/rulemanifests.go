package evals

import (
	"fmt"
	"strings"
)

// RenderRuleCampaign renders the namespace, source client, and target services
// of a rule campaign. Targets with deny paths get an Istio AuthorizationPolicy
// that the namespace waypoint enforces with 403.
func RenderRuleCampaign(campaign RuleCampaign) WorkloadContract {
	runtimeID := campaignRuntimeID("rule/" + campaign.ID)
	namespace := "aseval-" + runtimeID
	documents := []string{
		fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    %s: %s`, namespace, evalLabel, runtimeID),
		serviceAccount(namespace, runtimeID, campaign.Source),
		clientDeployment(namespace, runtimeID, campaign.Source),
	}
	for _, target := range campaign.Targets {
		documents = append(documents,
			serviceAccount(namespace, runtimeID, target.Name),
			serverDeployment(namespace, runtimeID, target.Name),
			service(namespace, runtimeID, target.Name),
		)
		if len(target.DenyPaths) > 0 {
			documents = append(documents, denyPathsPolicy(namespace, runtimeID, target))
		}
	}
	return WorkloadContract{Namespace: namespace, RuntimeID: runtimeID, Manifest: strings.Join(documents, "\n---\n"), Source: campaign.Source}
}

// denyPathsPolicy attaches to the namespace waypoint and scopes the denial to
// the target's host; a Service-attached policy did not enforce in ambient mode.
func denyPathsPolicy(namespace, campaign string, target RuleTarget) string {
	paths := make([]string, 0, len(target.DenyPaths))
	for _, path := range target.DenyPaths {
		paths = append(paths, fmt.Sprintf("%q", path))
	}
	host := fmt.Sprintf("%s.%s.svc.cluster.local", target.Name, namespace)
	return fmt.Sprintf(`apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: %s-deny-paths
  namespace: %s
  labels: {%s: %s}
spec:
  targetRefs:
  - {group: gateway.networking.k8s.io, kind: Gateway, name: waypoint}
  action: DENY
  rules:
  - to:
    - operation:
        hosts: [%q, %q]
        paths: [%s]`, target.Name, namespace, evalLabel, campaign, host, host+":*", strings.Join(paths, ", "))
}

// ruleBackgroundClients are the steady clients of the rule suite's background
// namespace: each loops over requests to the background services every few
// seconds, so the graph always holds mesh telemetry, as in a live cluster.
// They use fully qualified Service names because the Istio mapping resolves
// a waypoint request's destination from that authority.
var ruleBackgroundClients = []struct {
	name, script string
}{
	{"shop-web", `i=0; while true; do i=$((i+1)); curl -s -o /dev/null "http://catalog.$NAMESPACE.svc.cluster.local:8080/v1/products?page=$((i % 5))"; curl -s -o /dev/null http://profile.$NAMESPACE.svc.cluster.local:8080/v1/profile/me; sleep 5; done`},
	{"order-worker", `i=0; while true; do i=$((i+1)); curl -s -o /dev/null "http://orders.$NAMESPACE.svc.cluster.local:8080/v1/orders?status=open"; curl -s -o /dev/null -X POST "http://orders.$NAMESPACE.svc.cluster.local:8080/v1/orders/$((i % 50))/ack"; sleep 5; done`},
	{"catalog-indexer", `while true; do curl -s -o /dev/null http://catalog.$NAMESPACE.svc.cluster.local:8080/v1/products/changes; sleep 5; done`},
}

var ruleBackgroundServices = []string{"catalog", "orders", "profile"}

// RenderRuleBackground renders the namespace of steady background traffic that
// runs for the whole rule suite.
func RenderRuleBackground() WorkloadContract {
	runtimeID := campaignRuntimeID("rule/background")
	namespace := "aseval-" + runtimeID
	documents := []string{fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    %s: %s`, namespace, evalLabel, runtimeID)}
	for _, name := range ruleBackgroundServices {
		documents = append(documents, serviceAccount(namespace, runtimeID, name), serverDeployment(namespace, runtimeID, name), service(namespace, runtimeID, name))
	}
	for _, client := range ruleBackgroundClients {
		documents = append(documents, serviceAccount(namespace, runtimeID, client.name), loopClientDeployment(namespace, runtimeID, client.name, client.script))
	}
	return WorkloadContract{Namespace: namespace, RuntimeID: runtimeID, Manifest: strings.Join(documents, "\n---\n")}
}

func loopClientDeployment(namespace, campaign, name, script string) string {
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
        env:
        - name: NAMESPACE
          valueFrom: {fieldRef: {fieldPath: metadata.namespace}}
        command: ["sh", "-c", %q]`, metadata(namespace, campaign, name), name, name, name, evalLabel, campaign, name, script)
}
