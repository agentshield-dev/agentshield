package cilium

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCiliumEndpointSelectorMatchesSourcesAndSyntheticLabels(t *testing.T) {
	pod := object("v1", "Pod", "shop", "frontend", "pod-1", map[string]any{
		"metadata": map[string]any{"labels": map[string]any{"app": "frontend"}},
	})
	tests := []struct {
		name     string
		selector metav1.LabelSelector
		cluster  string
		want     bool
	}{
		{name: "unqualified source", selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}}, cluster: "cluster-a", want: true},
		{name: "Kubernetes source", selector: metav1.LabelSelector{MatchLabels: map[string]string{"k8s:app": "frontend"}}, cluster: "cluster-a", want: true},
		{name: "namespace", selector: metav1.LabelSelector{MatchLabels: map[string]string{"k8s:io.kubernetes.pod.namespace": "shop"}}, cluster: "cluster-a", want: true},
		{name: "cluster", selector: metav1.LabelSelector{MatchLabels: map[string]string{"k8s:io.cilium.k8s.policy.cluster": "cluster-a"}}, cluster: "cluster-a", want: true},
		{name: "other cluster", selector: metav1.LabelSelector{MatchLabels: map[string]string{"k8s:io.cilium.k8s.policy.cluster": "cluster-b"}}, cluster: "cluster-a", want: false},
		{name: "other source", selector: metav1.LabelSelector{MatchLabels: map[string]string{"reserved:app": "frontend"}}, cluster: "cluster-a", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selector, err := newCiliumEndpointSelector(test.selector)
			if err != nil {
				t.Fatal(err)
			}
			if got := selector.Matches(test.cluster, pod); got != test.want {
				t.Fatalf("Matches() = %t, want %t", got, test.want)
			}
		})
	}
}
