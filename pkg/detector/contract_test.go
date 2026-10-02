package detector

import (
	"slices"
	"strings"
	"testing"
)

func TestCELEnvironmentDeclaresOnlySelectorFields(t *testing.T) {
	description := CELExpressionDescription()
	for _, variable := range CELContractVariables() {
		if !strings.Contains(description, "`"+variable.Name+"` (`"+variable.Type()+"`)") {
			t.Fatalf("generated contract omits %s", variable.Name)
		}
	}
	for _, selector := range CELSelectors() {
		environment, err := CELEnvironment(selector.Type, selector.Kind)
		if err != nil {
			t.Fatal(err)
		}
		for _, variable := range CELContractVariables() {
			_, declared := selector.Fields[variable.Name]
			ast, issues := environment.Compile(variable.Name)
			if declared && (issues.Err() != nil || !ast.OutputType().IsExactType(variable.celType)) {
				t.Fatalf("%s: declared variable %s rejected: %v", selector.Name(), variable.Name, issues.Err())
			}
			if !declared && issues.Err() == nil {
				t.Fatalf("%s: unpopulated variable %s compiled", selector.Name(), variable.Name)
			}
		}
		for _, expression := range []string{"after.exists(a, true)", "workload.hostNetwork", "plugin_id == 'cilium'", "properties['destination-port'] == '443'"} {
			if _, issues := environment.Compile(expression); issues.Err() == nil {
				t.Fatalf("removed or host-selected field %q leaked into CEL", expression)
			}
		}
	}
	for _, value := range []string{"`public`", "`special`", "`control-plane-api`", "100.64.0.0/10"} {
		if !strings.Contains(description, value) {
			t.Fatalf("generated value catalog omits %s", value)
		}
	}
}

func TestCELSelectorsAreGeneratedFromRegistries(t *testing.T) {
	names := CELSelectorNames()
	for _, want := range []string{"relationship:communicates-with", "relationship:uses-identity", "telemetry:network-flow", "telemetry:gateway-request", "telemetry:active-probe"} {
		if !slices.Contains(names, want) {
			t.Fatalf("selectors=%v omit %s", names, want)
		}
		inputType, kind, ok := ParseCELSelector(want)
		if !ok || !ValidCELRuleKind(inputType, kind) {
			t.Fatalf("selector %s does not round-trip", want)
		}
	}
	for _, invalid := range [][2]string{{"telemetry", "communicates-with"}, {"relationship", "network-flow"}, {"resource", "kubernetes/deployment"}} {
		if ValidCELRuleKind(invalid[0], invalid[1]) {
			t.Fatalf("invalid selector %v accepted", invalid)
		}
	}
	variables := map[string]bool{}
	for _, variable := range CELContractVariables() {
		variables[variable.Name] = true
	}
	for _, selector := range CELSelectors() {
		for field := range selector.Fields {
			if !variables[field] {
				t.Fatalf("selector %s documents undeclared field %s", selector.Name(), field)
			}
		}
	}
}
