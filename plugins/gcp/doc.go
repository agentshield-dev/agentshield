// Package gcp is a Google Cloud Compute Engine source plugin for one project's
// instances, network interfaces, and VPC firewall rules.
//
// # Source and collections
//
// The plugin polls the Compute Engine instances and subnetworks aggregated
// list APIs and the firewalls list API with full pagination at startup and
// every poll interval. It authenticates only with Application Default
// Credentials, such as GKE Workload Identity, and never reads key files. All
// three calls must succeed, and an aggregated list that reports unreachable
// scopes fails the poll, so a snapshot is never partial. Each object is
// content-digested so retries keep stable event IDs, and the plugin publishes
// the gcp/compute/instances, firewalls, and subnetworks collections keyed by
// numeric resource ID. An optional region filter limits instances and
// subnetworks; firewall rules are global and always read.
//
// # Identity
//
// Resources use the cloud.google.com/v1 Resource scheme. The authority is the
// numeric project number. Firewall keys are compute/global/firewall/<id> with
// the immutable numeric ID. Instance keys are compute/<zone>/instance/<name>,
// and network interface keys append /network-interface/<nic>, because
// Kubernetes Node provider IDs and VPC Flow Logs name instances by zone and
// name, never by numeric ID; the numeric ID is the gcp/instance-id attribute.
// The source ID gcp/<project-number>[/<region>] identifies the observer.
// [Plugin.ResolveIdentityReference] turns a Kubernetes Node's
// gce://<project-id>/<zone>/<name> provider ID into an instance claim without
// reading the snapshot, so Kubernetes can assert Node backed-by instance in
// any publication order.
//
// # Graph output and failure behavior
//
// The "inventory" contribution asserts instances, network interfaces, and
// firewall rules; instance contains network interface; network interface
// exposes network destination for its internal and external addresses under
// the gcp/<host-project-id>/<network> realm; and network interface governed-by
// firewall rule. GCP firewall rules have no attachment, so governed-by is
// computed: an enabled rule governs a network interface on the same network
// when it has no targets or a target tag or target service account matches
// the instance. Each rule carries a gcp-firewall-rule facet with typed allow
// or deny security semantics and its priority. Coverage is partial:
// hierarchical and network firewall policies, implied rules, and rules in a
// Shared VPC host project outside this source are not read. An initial API
// failure prevents readiness. After a coherent publication, a failed poll
// republishes the last coherent input once with degraded health; recovery
// restores healthy status.
//
// See https://agent-shield.dev/docs/plugins/gcp/.
package gcp
