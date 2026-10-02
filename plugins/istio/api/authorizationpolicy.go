package api

import "encoding/json"

// UnmarshalJSON folds the deprecated singular targetRef into TargetRefs so
// projection handles one form.
func (spec *AuthorizationPolicySpec) UnmarshalJSON(data []byte) error {
	type authorizationPolicySpec AuthorizationPolicySpec
	decoded := struct {
		authorizationPolicySpec
		TargetRef *PolicyTargetReference `json:"targetRef,omitempty"`
	}{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*spec = AuthorizationPolicySpec(decoded.authorizationPolicySpec)
	if decoded.TargetRef != nil {
		spec.TargetRefs = append(spec.TargetRefs, *decoded.TargetRef)
	}
	return nil
}
