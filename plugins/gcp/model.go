package gcp

// Instance is the normalized Compute Engine instance observation published to
// the instances collection. Fields tagged json:"-" are delivery metadata
// excluded from the content digest.
type Instance struct {
	ID                string             `json:"id"`
	Name              string             `json:"name"`
	Zone              string             `json:"zone"`
	MachineType       string             `json:"machineType,omitempty"`
	Status            string             `json:"status,omitempty"`
	Tags              []string           `json:"tags,omitempty"`
	ServiceAccounts   []string           `json:"serviceAccounts,omitempty"`
	NetworkInterfaces []NetworkInterface `json:"networkInterfaces,omitempty"`
	Revision          string             `json:"-"`
	EventID           string             `json:"-"`
}

// NetworkInterface is one instance NIC. Network and Subnetwork are
// project-qualified relative paths such as projects/p/global/networks/n.
type NetworkInterface struct {
	Name          string   `json:"name"`
	Network       string   `json:"network"`
	Subnetwork    string   `json:"subnetwork,omitempty"`
	Addresses     []string `json:"addresses,omitempty"`
	AliasIPRanges []string `json:"aliasIpRanges,omitempty"`
}

// Firewall is the normalized VPC firewall rule observation. Lists are sorted
// so equivalent provider responses digest identically.
type Firewall struct {
	ID                    string       `json:"id"`
	Name                  string       `json:"name"`
	Network               string       `json:"network"`
	Direction             string       `json:"direction"`
	Priority              int64        `json:"priority"`
	Disabled              bool         `json:"disabled,omitempty"`
	Allowed               []Permission `json:"allowed,omitempty"`
	Denied                []Permission `json:"denied,omitempty"`
	SourceRanges          []string     `json:"sourceRanges,omitempty"`
	DestinationRanges     []string     `json:"destinationRanges,omitempty"`
	SourceTags            []string     `json:"sourceTags,omitempty"`
	SourceServiceAccounts []string     `json:"sourceServiceAccounts,omitempty"`
	TargetTags            []string     `json:"targetTags,omitempty"`
	TargetServiceAccounts []string     `json:"targetServiceAccounts,omitempty"`
	Revision              string       `json:"-"`
	EventID               string       `json:"-"`
}

// Permission is one protocol and its port ranges in a firewall rule.
type Permission struct {
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports,omitempty"`
}

// Subnetwork is the normalized regional subnetwork observation.
type Subnetwork struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Region          string           `json:"region"`
	Network         string           `json:"network"`
	IPCIDRRange     string           `json:"ipCidrRange,omitempty"`
	IPv6CIDRRange   string           `json:"ipv6CidrRange,omitempty"`
	SecondaryRanges []SecondaryRange `json:"secondaryRanges,omitempty"`
	Purpose         string           `json:"purpose,omitempty"`
	StackType       string           `json:"stackType,omitempty"`
	Revision        string           `json:"-"`
	EventID         string           `json:"-"`
}

// SecondaryRange is a named subnetwork secondary range, such as a GKE Pod or
// Service range.
type SecondaryRange struct {
	Name        string `json:"name"`
	IPCIDRRange string `json:"ipCidrRange"`
}

// Snapshot is one coherent, fully paginated read of all three Compute APIs.
// The projector only ever sees a complete snapshot.
type Snapshot struct {
	Instances   []Instance
	Firewalls   []Firewall
	Subnetworks []Subnetwork
}
