package kgateway

import (
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/coherentcache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ObservedObject is one cached Kubernetes observation with the event ID used
// as assertion evidence.
type ObservedObject = coherentcache.Object

// CoverageState is the projection-time view of one kgateway capability.
type CoverageState string

// Coverage states. NotInstalled means the CRD is not served by the cluster,
// which is never evidence that no policy exists.
const (
	CoverageStateCovered      CoverageState = "covered"
	CoverageStateNotInstalled CoverageState = "not-installed"
	CoverageStateDegraded     CoverageState = "degraded"
	CoverageStateUnknown      CoverageState = "unknown"
)

// ProjectionContext configures projection. Empty ControllerNames use
// [DefaultControllerName]; an empty NetworkID uses ClusterID. Coverage maps a
// kgateway capability to its state; a missing entry is unknown.
type ProjectionContext struct {
	ClusterID       string
	NetworkID       string
	SourceID        string
	ControllerNames []string
	Coverage        map[string]CoverageState
}

// ProjectionResult is the complete semantics contribution input plus
// diagnostics for references that could not be projected.
type ProjectionResult struct {
	Input       graph.Input
	Diagnostics []Diagnostic
}

// Diagnostic records a skipped or unresolved provider reference. Diagnostics
// are not graph facts and never imply that a reference is safe or absent.
type Diagnostic struct {
	Resource string
	Code     string
	Message  string
}

type objectMeta struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
}

type policyStatus struct {
	Ancestors []struct {
		ControllerName string             `json:"controllerName"`
		Conditions     []metav1.Condition `json:"conditions,omitempty"`
	} `json:"ancestors,omitempty"`
}

type targetReference struct {
	Group       string  `json:"group"`
	Kind        string  `json:"kind"`
	Name        string  `json:"name"`
	SectionName *string `json:"sectionName,omitempty"`
}

type targetSelector struct {
	Group       string            `json:"group"`
	Kind        string            `json:"kind"`
	MatchLabels map[string]string `json:"matchLabels"`
	SectionName *string           `json:"sectionName,omitempty"`
}

type namespacedReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type policyDisable struct{}

type trafficPolicy struct {
	objectMeta `json:",inline"`
	Spec       trafficPolicySpec `json:"spec"`
	Status     policyStatus      `json:"status,omitempty"`
}

type trafficPolicySpec struct {
	TargetRefs      []targetReference `json:"targetRefs,omitempty"`
	TargetSelectors []targetSelector  `json:"targetSelectors,omitempty"`
	ExtAuth         *struct {
		ExtensionRef *namespacedReference `json:"extensionRef,omitempty"`
		Disable      *policyDisable       `json:"disable,omitempty"`
	} `json:"extAuth,omitempty"`
	JWTAuth *struct {
		ExtensionRef *namespacedReference `json:"extensionRef,omitempty"`
		Disable      *policyDisable       `json:"disable,omitempty"`
	} `json:"jwtAuth,omitempty"`
	BasicAuth *struct {
		Users     []string       `json:"users,omitempty"`
		SecretRef *struct{}      `json:"secretRef,omitempty"`
		Disable   *policyDisable `json:"disable,omitempty"`
	} `json:"basicAuth,omitempty"`
	APIKeyAuth *struct {
		Disable *policyDisable `json:"disable,omitempty"`
	} `json:"apiKeyAuth,omitempty"`
	OAuth2 *struct {
		ExtensionRef namespacedReference `json:"extensionRef"`
	} `json:"oauth2,omitempty"`
	RBAC *struct {
		Action string `json:"action,omitempty"`
		Policy struct {
			MatchExpressions []string `json:"matchExpressions"`
		} `json:"policy"`
	} `json:"rbac,omitempty"`
	ACL *struct {
		DefaultAction string `json:"defaultAction"`
		Rules         []struct {
			Action string `json:"action"`
		} `json:"rules,omitempty"`
	} `json:"acl,omitempty"`
}

type listenerPolicy struct {
	objectMeta `json:",inline"`
	Spec       struct {
		TargetRefs      []targetReference `json:"targetRefs,omitempty"`
		TargetSelectors []targetSelector  `json:"targetSelectors,omitempty"`
		Default         *listenerConfig   `json:"default,omitempty"`
		PerPort         []struct {
			Port     int32           `json:"port"`
			Listener *listenerConfig `json:"listener,omitempty"`
		} `json:"perPort,omitempty"`
	} `json:"spec"`
}

type listenerConfig struct {
	HTTPSettings *struct {
		AccessLog []struct {
			FileSink      *struct{} `json:"fileSink,omitempty"`
			GrpcService   *struct{} `json:"grpcService,omitempty"`
			OpenTelemetry *struct{} `json:"openTelemetry,omitempty"`
		} `json:"accessLog,omitempty"`
		UseRemoteAddress  *bool    `json:"useRemoteAddress,omitempty"`
		XffNumTrustedHops *int32   `json:"xffNumTrustedHops,omitempty"`
		XffTrustedCIDRs   []string `json:"xffTrustedCIDRs,omitempty"`
	} `json:"httpSettings,omitempty"`
}

type backendConfigPolicy struct {
	objectMeta `json:",inline"`
	Spec       struct {
		TargetRefs      []targetReference `json:"targetRefs,omitempty"`
		TargetSelectors []targetSelector  `json:"targetSelectors,omitempty"`
		TLS             *backendTLS       `json:"tls,omitempty"`
	} `json:"spec"`
}

type backendTLS struct {
	SecretRef               *struct{} `json:"secretRef,omitempty"`
	Files                   *struct{} `json:"files,omitempty"`
	WellKnownCACertificates *string   `json:"wellKnownCACertificates,omitempty"`
	InsecureSkipVerify      *bool     `json:"insecureSkipVerify,omitempty"`
	Sni                     *string   `json:"sni,omitempty"`
	VerifySubjectAltNames   []string  `json:"verifySubjectAltNames,omitempty"`
	SimpleTLS               *bool     `json:"simpleTLS,omitempty"`
}

type backend struct {
	objectMeta `json:",inline"`
	Spec       struct {
		Type   string `json:"type,omitempty"`
		Static *struct {
			Hosts []struct {
				Host string `json:"host"`
				Port int32  `json:"port"`
			} `json:"hosts"`
		} `json:"static,omitempty"`
		DynamicForwardProxy *struct {
			EnableTLS *bool `json:"enableTls,omitempty"`
		} `json:"dynamicForwardProxy,omitempty"`
		AWS *struct {
			AccountID string `json:"accountId,omitempty"`
			Region    string `json:"region,omitempty"`
		} `json:"aws,omitempty"`
		GCP *struct {
			Host string `json:"host"`
		} `json:"gcp,omitempty"`
		PriorityGroups []struct{} `json:"priorityGroups,omitempty"`
	} `json:"spec"`
}

type directResponse struct {
	objectMeta `json:",inline"`
	Spec       struct {
		StatusCode int32   `json:"status"`
		Body       *string `json:"body,omitempty"`
	} `json:"spec"`
}

type gatewayExtension struct {
	objectMeta `json:",inline"`
	Spec       struct {
		Type      string    `json:"type,omitempty"`
		ExtAuth   *struct{} `json:"extAuth,omitempty"`
		ExtProc   *struct{} `json:"extProc,omitempty"`
		RateLimit *struct{} `json:"rateLimit,omitempty"`
		JWT       *struct{} `json:"jwt,omitempty"`
		OAuth2    *struct{} `json:"oauth2,omitempty"`
	} `json:"spec"`
}

type gatewayParameters struct {
	objectMeta `json:",inline"`
	Spec       struct {
		Kube *struct {
			Service *struct {
				Type *string `json:"type,omitempty"`
			} `json:"service,omitempty"`
		} `json:"kube,omitempty"`
		SelfManaged *struct{} `json:"selfManaged,omitempty"`
	} `json:"spec"`
}

type gatewayClass struct {
	objectMeta `json:",inline"`
	Spec       struct {
		ControllerName string `json:"controllerName"`
		ParametersRef  *struct {
			Group     string `json:"group"`
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace,omitempty"`
		} `json:"parametersRef,omitempty"`
	} `json:"spec"`
}

type gateway struct {
	objectMeta `json:",inline"`
	Spec       struct {
		GatewayClassName string `json:"gatewayClassName"`
		Infrastructure   *struct {
			ParametersRef *struct {
				Group string `json:"group"`
				Kind  string `json:"kind"`
				Name  string `json:"name"`
			} `json:"parametersRef,omitempty"`
		} `json:"infrastructure,omitempty"`
	} `json:"spec"`
}

type httpRoute struct {
	objectMeta `json:",inline"`
	Spec       struct {
		Rules []struct {
			Name        *string `json:"name,omitempty"`
			BackendRefs []struct {
				Group     string `json:"group,omitempty"`
				Kind      string `json:"kind,omitempty"`
				Namespace string `json:"namespace,omitempty"`
				Name      string `json:"name"`
				Port      *int32 `json:"port,omitempty"`
				Weight    *int32 `json:"weight,omitempty"`
			} `json:"backendRefs,omitempty"`
			Filters []struct {
				Type         string `json:"type"`
				ExtensionRef *struct {
					Group string `json:"group"`
					Kind  string `json:"kind"`
					Name  string `json:"name"`
				} `json:"extensionRef,omitempty"`
			} `json:"filters,omitempty"`
		} `json:"rules,omitempty"`
	} `json:"spec"`
}
