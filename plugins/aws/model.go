package aws

// NetworkInterface is the normalized ENI observation published to the
// network-interfaces collection. Fields tagged json:"-" are delivery metadata
// excluded from the content digest.
type NetworkInterface struct {
	ID                   string   `json:"id"`
	OwnerID              string   `json:"ownerId"`
	VPCID                string   `json:"vpcId,omitempty"`
	SubnetID             string   `json:"subnetId,omitempty"`
	AvailabilityZone     string   `json:"availabilityZone,omitempty"`
	InterfaceType        string   `json:"interfaceType,omitempty"`
	Status               string   `json:"status,omitempty"`
	RequesterManaged     bool     `json:"requesterManaged,omitempty"`
	AttachmentInstanceID string   `json:"attachmentInstanceId,omitempty"`
	SecurityGroupIDs     []string `json:"securityGroupIds,omitempty"`
	Addresses            []string `json:"addresses,omitempty"`
	Revision             string   `json:"-"`
	EventID              string   `json:"-"`
}

// Instance is the normalized EC2 instance observation.
type Instance struct {
	ID               string `json:"id"`
	OwnerID          string `json:"ownerId"`
	VPCID            string `json:"vpcId,omitempty"`
	SubnetID         string `json:"subnetId,omitempty"`
	AvailabilityZone string `json:"availabilityZone,omitempty"`
	InstanceType     string `json:"instanceType,omitempty"`
	State            string `json:"state,omitempty"`
	Revision         string `json:"-"`
	EventID          string `json:"-"`
}

// SecurityGroup is the normalized security group observation with its
// ingress and egress rules.
type SecurityGroup struct {
	ID       string `json:"id"`
	OwnerID  string `json:"ownerId"`
	VPCID    string `json:"vpcId,omitempty"`
	Name     string `json:"name,omitempty"`
	Ingress  []Rule `json:"ingress"`
	Egress   []Rule `json:"egress"`
	Revision string `json:"-"`
	EventID  string `json:"-"`
}

// Rule is one normalized security group permission. Lists are sorted so
// equivalent provider responses digest identically.
type Rule struct {
	Protocol         string   `json:"protocol"`
	FromPort         *int32   `json:"fromPort,omitempty"`
	ToPort           *int32   `json:"toPort,omitempty"`
	IPv4Ranges       []string `json:"ipv4Ranges,omitempty"`
	IPv6Ranges       []string `json:"ipv6Ranges,omitempty"`
	PrefixListIDs    []string `json:"prefixListIds,omitempty"`
	SecurityGroupIDs []string `json:"securityGroupIds,omitempty"`
}

// Snapshot is one coherent, fully paginated read of all three EC2 APIs. The
// projector only ever sees a complete snapshot.
type Snapshot struct {
	NetworkInterfaces []NetworkInterface
	Instances         []Instance
	SecurityGroups    []SecurityGroup
}
