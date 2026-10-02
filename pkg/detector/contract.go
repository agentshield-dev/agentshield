package detector

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

// CELVariable describes one [Input] field as a CEL variable.
type CELVariable struct {
	Name        string
	Description string
	celType     *cel.Type
}

// CELSelector is one evaluable (input type, kind) pair; only its Fields are declared to CEL.
type CELSelector struct {
	Type        string
	Kind        string
	Description string
	Trigger     string
	Fields      map[string]string
}

// Name returns the selector as "type:kind".
func (selector CELSelector) Name() string { return selector.Type + ":" + selector.Kind }

// CELSelectors returns every evaluable selector: one relationship selector per
// registered graph predicate and one telemetry selector per telemetry event
// kind. It is the single catalog used for rule validation, authoring schemas,
// and documentation.
func CELSelectors() []CELSelector {
	var selectors []CELSelector
	for _, predicate := range graph.RegisteredPredicateDescriptions() {
		selector := CELSelector{
			Type: "relationship", Kind: string(predicate.Predicate), Description: predicate.Description,
			Trigger: "once when a new edge of this predicate appears in the graph",
		}
		if predicate.Predicate == graph.PredicateCommunicates {
			selector.Fields = map[string]string{
				"destination_ip_class": "class of the object's IP address; `unknown` when the object is not an IP destination",
				"destination_role":     "role of the object in the cluster",
			}
		}
		if predicate.Predicate == graph.PredicateExecutes {
			selector.Fields = map[string]string{"process_class": "class of the process the subject workload started"}
		}
		selectors = append(selectors, selector)
	}
	for _, kind := range telemetry.EventKinds() {
		fields := map[string]string{"operation": kind.Operation, "outcome": kind.Outcome}
		if kind.Lease == graph.PredicateCommunicates {
			fields["destination_role"] = "role of the object endpoint in the cluster"
		}
		if kind.DestinationIPClass {
			fields["destination_ip_class"] = "class of the object endpoint's IP address"
		}
		if kind.Lease == graph.PredicateExecutes {
			fields["process_class"] = "class of the process the subject workload started"
		}
		selectors = append(selectors, CELSelector{
			Type: "telemetry", Kind: kind.Kind, Description: kind.Description, Fields: fields,
			Trigger: "once per newly observed combination of endpoints, operation, and outcome",
		})
	}
	return selectors
}

// CELSelectorNames returns the "type:kind" name of every selector.
func CELSelectorNames() []string {
	selectors := CELSelectors()
	names := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		names = append(names, selector.Name())
	}
	return names
}

func lookupCELSelector(inputType, kind string) (CELSelector, bool) {
	for _, selector := range CELSelectors() {
		if selector.Type == inputType && selector.Kind == kind {
			return selector, true
		}
	}
	return CELSelector{}, false
}

// ParseCELSelector splits a "type:kind" name and reports whether it names a
// known selector.
func ParseCELSelector(name string) (inputType, kind string, ok bool) {
	inputType, kind, found := strings.Cut(name, ":")
	if !found {
		return "", "", false
	}
	if _, ok := lookupCELSelector(inputType, kind); !ok {
		return "", "", false
	}
	return inputType, kind, true
}

// ValidCELRuleKind reports whether (inputType, kind) is a known selector.
func ValidCELRuleKind(inputType, kind string) bool {
	_, ok := lookupCELSelector(inputType, kind)
	return ok
}

// Type returns the variable's CEL type name.
func (variable CELVariable) Type() string { return variable.celType.String() }

// CELContractVariables returns every [Input] field as a CEL variable, named by
// its JSON tag.
func CELContractVariables() []CELVariable {
	typ := reflect.TypeOf(Input{})
	variables := make([]CELVariable, 0, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		variables = append(variables, CELVariable{Name: name, Description: field.Tag.Get("cel_description"), celType: cel.StringType})
	}
	return variables
}

// CELEnvironment declares only the variables the selector populates.
func CELEnvironment(inputType, kind string) (*cel.Env, error) {
	selector, ok := lookupCELSelector(inputType, kind)
	if !ok {
		return nil, fmt.Errorf("unsupported selector %q", inputType+":"+kind)
	}
	var options []cel.EnvOption
	for _, variable := range CELContractVariables() {
		if _, populated := selector.Fields[variable.Name]; populated {
			options = append(options, cel.Variable(variable.Name, variable.celType))
		}
	}
	return cel.NewEnv(options...)
}

func celVariableValues() map[string][]string {
	values := map[string][]string{}
	for _, class := range telemetry.DestinationIPClasses() {
		values["destination_ip_class"] = append(values["destination_ip_class"], fmt.Sprintf("`%s` (%s)", class.Class, class.Description))
	}
	for _, role := range graph.NetworkRoles() {
		values["destination_role"] = append(values["destination_role"], fmt.Sprintf("`%s` (%s)", role.Role, role.Description))
	}
	values["destination_role"] = append(values["destination_role"], "empty string (the address belongs to no known cluster resource)")
	for _, class := range graph.ProcessClasses() {
		values["process_class"] = append(values["process_class"], fmt.Sprintf("`%s` (%s)", class.Class, class.Description))
	}
	return values
}

// CELSelectorDescription renders the selector catalog as text for a model
// authoring schema.
func CELSelectorDescription() string {
	return CELSelectorDescriptionFor(nil)
}

// CELSelectorDescriptionFor documents the named selectors; nil documents every selector.
func CELSelectorDescriptionFor(names []string) string {
	var contract strings.Builder
	contract.WriteString("The graph input the rule evaluates. The host scopes every rule to inputs connected to the target workload. Selectors:\n")
	variables := CELContractVariables()
	for _, selector := range CELSelectors() {
		if names != nil && !slices.Contains(names, selector.Name()) {
			continue
		}
		fmt.Fprintf(&contract, "- `%s`: %s Evaluated %s.", selector.Name(), selector.Description, selector.Trigger)
		if len(selector.Fields) == 0 {
			contract.WriteString(" Declares no expression variables.\n")
			continue
		}
		var populated []string
		for _, variable := range variables {
			if description, ok := selector.Fields[variable.Name]; ok {
				populated = append(populated, fmt.Sprintf("`%s` (%s)", variable.Name, description))
			}
		}
		fmt.Fprintf(&contract, " Declares %s.\n", strings.Join(populated, "; "))
	}
	return contract.String()
}

// CELExpressionDescription renders the CEL variable contract, with allowed
// values, as text for a model authoring schema.
func CELExpressionDescription() string {
	var contract strings.Builder
	contract.WriteString("A CEL boolean expression. Only the variables the chosen selector declares are available; referencing any other variable fails to compile. Variables:\n")
	values := celVariableValues()
	for _, variable := range CELContractVariables() {
		fmt.Fprintf(&contract, "- `%s` (`%s`): %s", variable.Name, variable.Type(), variable.Description)
		if allowed := values[variable.Name]; len(allowed) > 0 {
			fmt.Fprintf(&contract, " Values: %s.", strings.Join(allowed, "; "))
		}
		contract.WriteString("\n")
	}
	return contract.String()
}
