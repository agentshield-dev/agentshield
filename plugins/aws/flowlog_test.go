package aws

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeVPCFlowLogDirectionAndStableIdentity(t *testing.T) {
	scope := ProjectionContext{Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1"}
	tests := []struct {
		name              string
		direction         string
		packetSource      string
		packetDestination string
		wantSubjectKey    string
		wantObjectKey     string
	}{
		{name: "ingress", direction: "ingress", packetSource: "198.51.100.10", packetDestination: "10.0.0.2", wantSubjectKey: "ip/198.51.100.10", wantObjectKey: "aws/ec2/us-east-1/network-interface/eni-abc"},
		{name: "egress", direction: "egress", packetSource: "10.0.0.1", packetDestination: "203.0.113.20", wantSubjectKey: "aws/ec2/us-east-1/network-interface/eni-abc", wantObjectKey: "ip/203.0.113.20"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			line := flowLogLine(test.direction, test.packetSource, test.packetDestination, "OK")
			event, err := NormalizeVPCFlowLog(scope, line)
			if err != nil {
				t.Fatal(err)
			}
			if event.Subject.ImmutableKey != test.wantSubjectKey || event.Object.ImmutableKey != test.wantObjectKey {
				t.Fatalf("direction = %s -> %s", event.Subject.ImmutableKey, event.Object.ImmutableKey)
			}
			if event.PluginID != PluginID || event.SourceID != scope.SourceID || event.Operation != test.direction || event.Outcome != "allowed" || event.Count != 7 {
				t.Fatalf("event = %#v", event)
			}
			if event.ObservedAt != time.Unix(1_700_000_060, 0).UTC() || event.Properties["protocol"] != "tcp" || event.Properties["traffic-path"] != "2" {
				t.Fatalf("timestamp/properties = %s %#v", event.ObservedAt, event.Properties)
			}
			retry, err := NormalizeVPCFlowLog(scope, "  "+strings.ReplaceAll(line, " ", "   ")+"  ")
			if err != nil {
				t.Fatal(err)
			}
			if retry.EventID != event.EventID || retry.ObservedAt != event.ObservedAt {
				t.Fatalf("retry identity changed: %q != %q", retry.EventID, event.EventID)
			}
		})
	}
}

func TestNormalizeVPCFlowLogRejectsMalformedRecord(t *testing.T) {
	scope := ProjectionContext{Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1"}
	if _, err := NormalizeVPCFlowLog(scope, flowLogLine("sideways", "-", "-", "OK")); err == nil {
		t.Fatal("unsupported direction was accepted")
	}
	if _, err := NormalizeVPCFlowLog(scope, flowLogLine("ingress", "-", "-", "SKIPDATA")); !errors.Is(err, errNoFlowData) {
		t.Fatalf("SKIPDATA error = %v", err)
	}
}

func flowLogLine(direction, packetSource, packetDestination, status string) string {
	return strings.Join([]string{
		"5", "111111111111", "eni-abc", "10.0.0.1", "10.0.0.2", "12345", "443", "6", "7", "700",
		"1700000000", "1700000060", "ACCEPT", status, "vpc-abc", "subnet-abc", "i-abc", "2", "IPv4",
		packetSource, packetDestination, "us-east-1", "use1-az1", direction, "2",
	}, " ")
}
