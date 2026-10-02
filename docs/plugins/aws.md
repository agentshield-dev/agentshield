# AWS plugin

The `aws` plugin inventories EC2 instances, Elastic Network Interfaces (ENIs), and Security Groups in one region, and can receive VPC Flow Logs directly from Amazon Data Firehose. It lets AgentShield connect cloud network policy to Kubernetes Nodes and to observed traffic.

It does not inventory VPCs, subnets, route tables, internet or NAT gateways, network ACLs, or IAM, and it has no remediation actions.

Code: `plugins/aws`.

## Summary

| | |
| --- | --- |
| Plugin ID, version | `aws`, `0.1.0` |
| Role | Source plugin; provider-native telemetry receiver |
| Enabled by | `--aws-region` |
| Credentials | Default AWS SDK credential chain (`AWS_PROFILE`, environment, instance role, ...) |
| Source ID | `aws/<partition>/<caller account>/<region>`, from STS `GetCallerIdentity` at startup |
| Authority | The 12-digit `OwnerId` of each resource |
| Identity scheme | `aws.amazon.com/v1, Kind=Resource` |
| Keys | `<partition>/ec2/<region>/network-interface/<eni-id>`, `.../instance/<instance-id>`, `.../security-group/<sg-id>` |
| Contribution | `inventory` |
| Collections | `aws/ec2/<region>/network-interfaces`, `aws/ec2/<region>/instances`, `aws/ec2/<region>/security-groups` |
| Provider cursor | None. SQS receipt handles are acknowledgements, not state. |

The caller account identifies the *source*; each resource's owner account is its *authority*. This keeps ENIs owned by other accounts in a shared VPC, and shared Security Groups, under their real owners.

Switching credentials to another account creates a new source ID. The old source's contribution is not retired automatically; retire it separately.

## Running

```bash
AWS_PROFILE=example go run ./cmd/agentshield \
  --kubernetes-disable \
  --aws-region us-east-1 \
  --aws-events-queue-url https://sqs.us-east-1.amazonaws.com/111111111111/agentshield-aws-events
```

`--aws-events-queue-url` is optional. Without it, the plugin reconciles every 5 minutes. Drop `--kubernetes-disable` to run AWS and Kubernetes discovery in one process; then Kubernetes Nodes whose `spec.providerID` points at an inventoried instance get a `backed-by` edge to it. Only the `aws:///<zone>/<instance-id>` form in the source's region resolves; a zone in another region, an EKS Fargate ID, or any other form stays unmatched rather than failing the Kubernetes projection.

### Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups"
  ],
  "Resource": "*"
}
```

With `--aws-events-queue-url`, also:

```json
{
  "Effect": "Allow",
  "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
  "Resource": "arn:aws:sqs:us-east-1:111111111111:agentshield-aws-events"
}
```

`sts:GetCallerIdentity` needs no explicit permission. The plugin never logs credentials.

## Reconciliation

At startup, every 5 minutes, and whenever a matching SQS event arrives, the plugin:

1. Pages through all three Describe APIs completely.
2. Normalizes each object and computes a content digest, so retries produce the same event IDs.
3. Publishes upserts for changed objects and deletes for missing ones.
4. Replaces the whole `inventory` contribution.
5. Marks all three collections ready at the same generation.

The generation is recovered at startup and only increases.

If the first reconciliation fails (API, decoding, or validation error), the plugin never becomes ready. After a successful one, the first failed poll republishes the last good input with degraded health. Later failures do not create more generations. The next successful poll restores healthy status.

EC2 APIs are eventually consistent, so a poll may briefly miss a very recent change. The next poll converges. There is no artificial delay before deletions.

## Change events (optional)

CloudTrail records EC2 API calls; an EventBridge rule forwards them to an SQS queue; the plugin long-polls the queue (10 messages, 20-second wait, 5-minute visibility timeout) and reconciles when an event matches. The queue, its dead-letter queue, the trail, and the rule are yours to create. Create the queue before starting AgentShield so changes during the first reconciliation are kept.

Send the original event to SQS without an input transformer. Rule pattern:

```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "AssignIpv6Addresses", "AssignPrivateIpAddresses", "AssociateSecurityGroupVpc",
      "AttachNetworkInterface", "AuthorizeSecurityGroupEgress", "AuthorizeSecurityGroupIngress",
      "CreateNetworkInterface", "CreateSecurityGroup", "DeleteNetworkInterface",
      "DeleteSecurityGroup", "DetachNetworkInterface", "DisassociateSecurityGroupVpc",
      "ModifyNetworkInterfaceAttribute", "ModifyInstanceAttribute", "ModifySecurityGroupRules",
      "RebootInstances", "ResetNetworkInterfaceAttribute", "RevokeSecurityGroupEgress",
      "RevokeSecurityGroupIngress", "RunInstances", "StartInstances", "StopInstances",
      "TerminateInstances", "UnassignIpv6Addresses", "UnassignPrivateIpAddresses",
      "UpdateSecurityGroupRuleDescriptionsEgress", "UpdateSecurityGroupRuleDescriptionsIngress"
    ]
  }
}
```

The queue policy must allow `events.amazonaws.com` to call `sqs:SendMessage`, restricted to the rule ARN. A standard queue is enough; order and exactly-once delivery do not matter because every event triggers a full read. Configure a redrive policy.

Message handling:

- A batch is deleted only after a successful reconciliation and readiness update. A failed reconciliation leaves messages for redelivery.
- Events for other accounts or regions, failed API calls, and unmatched event names are deleted without reconciling.
- Malformed messages (undecodable JSON or missing CloudTrail fields) are deleted with the rest of the batch and logged by SQS message ID, never by body; `SQSSubscriber.Discarded` counts them. They can never become valid, and the periodic poll covers any change they described. The redrive policy still catches messages that repeatedly fail for other reasons.

`InventoryEventSubscriptions` in `plugins/aws/subscription.go` declares which event names affect which collection. To add an inventory type, extend it together with the adapter and projector.

CloudTrail only covers calls in the caller's account. Resources in a shared VPC can be changed by another account without an event here; the periodic poll catches those.

## Graph output

Resources: `aws/ec2-instance`, `aws/ec2-network-interface`, `aws/ec2-security-group`. VPC, subnet, and attachment IDs are attributes.

Each current private, public, and IPv6 ENI address becomes a `network/destination` resource with an `exposes` edge from the ENI, so flow logs can resolve to the ENI.

An observed Security Group attachment emits `network interface --governed-by--> security group` with declared, bidirectional, partial network-access governance and `effect=unknown`. AWS applies the union of all Security Groups on an ENI, so one attachment does not prove restriction. An attachment is projected only when the group is in the same snapshot and its owner is known; otherwise it is recorded as an ENI diagnostic.

Each Security Group has two `aws-security-group-rules` facets, keyed `ingress` and `egress`. A non-empty direction carries declared `allow`; an empty one carries declared `restrict`. Coverage is `partial` because CIDRs, port ranges, prefix lists, group references, ICMP type/code, and stateful return traffic are not in the neutral summary. Native attributes keep sorted CIDRs, prefix lists, group references, protocols, and port bounds, capped at 100 rules per direction and 100 values per peer type with omitted counts. The configuration digest covers the complete direction. Only single-port TCP and UDP rules produce typed ports; protocol `-1` becomes `ALL`.

The plugin never claims external exposure from a public address or a `0.0.0.0/0` rule, because route tables, gateways, and network ACLs are not observed.

## VPC Flow Log telemetry

```text
VPC Flow Logs -> Amazon Data Firehose -> AgentShield -> raw sink and rollups
```

No OpenTelemetry Collector is needed.

1. Create a Firehose delivery stream with Direct PUT as the source and an HTTP endpoint destination: `https://<agentshield-host>/v1/aws/firehose/vpc-flow-logs`. Firehose requires HTTPS on port 443, so put AgentShield behind a load balancer or gateway that exposes only this route.
2. Set the stream's access key in `AGENTSHIELD_AWS_FIREHOSE_ACCESS_KEY`.
3. Start AgentShield with `--aws-region` and `--aws-firehose-stream-arn arn:aws:firehose:<region>:<account>:deliverystream/<name>`. The stream must be in the plugin's account and region.
4. Create the flow log with one-minute aggregation, traffic type `ALL`, and exactly this format:

```text
${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${flow-direction} ${traffic-path}
```

```bash
export AGENTSHIELD_AWS_FIREHOSE_ACCESS_KEY='<delivery-stream-access-key>'
AWS_PROFILE=example go run ./cmd/agentshield \
  --kubernetes-disable \
  --aws-region us-east-1 \
  --aws-firehose-stream-arn arn:aws:firehose:us-east-1:111111111111:deliverystream/agentshield-vpc-flow-logs
```

Each request must use Firehose protocol version `1.0`, carry the configured stream ARN and access key, and repeat the request ID in header and body. Plain and gzip-compressed envelopes are accepted, up to 96 MiB. Any non-200 response makes Firehose retry the batch. At most 4 deliveries are handled at once; more, or a batch the telemetry queue cannot take whole, get `429`. A batch larger than the whole queue gets `413`, and a pipeline that is shutting down gives `503`.

Records must be version 5 with status `OK`, an ENI, a VPC, the configured region, IPv4 or IPv6 addresses, and an ingress or egress direction. `NODATA` and `SKIPDATA` records are acknowledged and skipped. Any other invalid record rejects the whole request, so Firehose retries it or writes it to its S3 error backup.

Each record becomes a `network-flow` event:

- observation time: the end of the flow window;
- operation `ingress` or `egress`; outcome `allowed` (`ACCEPT`) or `denied` (`REJECT`);
- coverage `aws-vpc-flow-log`; count: packets;
- properties: protocol, source port, destination port, optional traffic path;
- the ENI as one endpoint and the peer address as a network destination scoped to partition, account, region, and VPC. Ingress is peer to ENI; egress is ENI to peer;
- event and evidence ID: a digest of the source ID and the complete record.

The receiver acknowledges Firehose once the in-memory queue accepts the batch, before the sink commits, so a crash can lose acknowledged records that Firehose will not resend (see [Telemetry failure behavior](../architecture/telemetry.md#failure-behavior)). The pipeline does not deduplicate by event ID. Size Firehose retry duration and S3 error backup with that in mind.

## Testing

`make test-aws-e2e` creates a disposable kind cluster with LocalStack, PostgreSQL, and AgentShield. It checks startup inventory, a Security Group update triggered through EventBridge and SQS, ENI removal, and a Firehose-format flow log reaching the JSONL sink. It sends synthetic CloudTrail-shaped events and Firehose envelopes; it does not test real CloudTrail, VPC Flow Logs, or Firehose delivery. Requirements are in [Testing](../development/testing.md#aws-end-to-end).

## Scale

Each reconciliation is linear in ENIs, instances, Security Groups, attachments, and rules, and buffers the full API results to publish one coherent snapshot.

## AWS references

- [DescribeNetworkInterfaces](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNetworkInterfaces.html), [DescribeSecurityGroups](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html), [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
- [EC2 eventual consistency](https://docs.aws.amazon.com/ec2/latest/devguide/eventual-consistency.html)
- [CloudTrail events in EventBridge](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html), [SQS as an EventBridge target](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-targets.html#targets-specifics-sqs), [SQS visibility timeout](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html)
- [VPC Flow Logs through Firehose](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-firehose.html), [Firehose HTTP request and response format](https://docs.aws.amazon.com/firehose/latest/dev/httpdeliveryrequestresponse.html), [VPC Flow Log fields](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
