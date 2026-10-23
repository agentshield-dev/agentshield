package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"

	awsdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

const (
	cloudTrailDetailType = "AWS API Call via CloudTrail"
	ec2EventSource       = "ec2.amazonaws.com"
)

// EventSubscription names one inventory collection and the CloudTrail events
// that can change it.
type EventSubscription struct {
	Name        string
	Source      string
	EventSource string
	EventNames  []string
}

// ChangeBatch is one received set of notifications. Subscriptions lists the
// matched subscription names; the batch must be acknowledged only after the
// resulting reconciliation is published.
type ChangeBatch struct {
	Subscriptions []string
	messages      []queuedMessage
}

// EventSubscriber delivers change notifications that trigger an immediate
// full reconciliation. Notifications are hints, not state: missing or
// duplicate notifications only change latency.
type EventSubscriber interface {
	Receive(context.Context) (ChangeBatch, error)
	Acknowledge(context.Context, ChangeBatch) error
}

// SQSAPI is the subset of the SQS client used by [SQSSubscriber].
type SQSAPI interface {
	ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessageBatch(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error)
}

// SQSSubscriberConfig binds a queue to the account and region whose events
// are accepted; events for any other account or region are acknowledged
// without reconciliation.
type SQSSubscriberConfig struct {
	QueueURL      string
	AccountID     string
	Region        string
	Subscriptions []EventSubscription
}

// SQSSubscriber long-polls an SQS queue that receives EventBridge CloudTrail
// events.
type SQSSubscriber struct {
	client    SQSAPI
	queueURL  string
	accountID string
	region    string
	events    map[string]string
	// discarded counts malformed messages deleted without reconciling.
	discarded atomic.Uint64
}

type queuedMessage struct {
	receipt string
}

type cloudTrailEvent struct {
	ID         string `json:"id"`
	Source     string `json:"source"`
	DetailType string `json:"detail-type"`
	Account    string `json:"account"`
	Region     string `json:"region"`
	Detail     struct {
		EventID     string `json:"eventID"`
		EventSource string `json:"eventSource"`
		EventName   string `json:"eventName"`
		ErrorCode   string `json:"errorCode"`
	} `json:"detail"`
}

// InventoryEventSubscriptions declares the CloudTrail EC2 events that affect
// each inventory collection. The EventBridge rule documented in
// https://agent-shield.dev/docs/plugins/aws/ must cover the same event names.
func InventoryEventSubscriptions() []EventSubscription {
	return []EventSubscription{
		{
			Name:        "instances",
			Source:      "aws.ec2",
			EventSource: ec2EventSource,
			EventNames: []string{
				"ModifyInstanceAttribute", "RebootInstances", "RunInstances", "StartInstances", "StopInstances", "TerminateInstances",
			},
		},
		{
			Name:        "network-interfaces",
			Source:      "aws.ec2",
			EventSource: ec2EventSource,
			EventNames: []string{
				"AssignIpv6Addresses", "AssignPrivateIpAddresses", "AttachNetworkInterface", "CreateNetworkInterface",
				"DeleteNetworkInterface", "DetachNetworkInterface", "ModifyNetworkInterfaceAttribute", "ResetNetworkInterfaceAttribute",
				"UnassignIpv6Addresses", "UnassignPrivateIpAddresses",
			},
		},
		{
			Name:        "security-groups",
			Source:      "aws.ec2",
			EventSource: ec2EventSource,
			EventNames: []string{
				"AssociateSecurityGroupVpc", "AuthorizeSecurityGroupEgress", "AuthorizeSecurityGroupIngress", "CreateSecurityGroup",
				"DeleteSecurityGroup", "DisassociateSecurityGroupVpc", "ModifySecurityGroupRules", "RevokeSecurityGroupEgress",
				"RevokeSecurityGroupIngress", "UpdateSecurityGroupRuleDescriptionsEgress", "UpdateSecurityGroupRuleDescriptionsIngress",
			},
		},
	}
}

// NewSQSSubscriber validates config and indexes the subscribed events.
func NewSQSSubscriber(client SQSAPI, config SQSSubscriberConfig) (*SQSSubscriber, error) {
	if client == nil {
		return nil, errors.New("AWS event subscriber requires an SQS client")
	}
	config.QueueURL = strings.TrimSpace(config.QueueURL)
	config.AccountID = strings.TrimSpace(config.AccountID)
	config.Region = strings.TrimSpace(config.Region)
	if config.QueueURL == "" || !validAccountID(config.AccountID) || config.Region == "" {
		return nil, errors.New("AWS event subscriber requires queue URL, 12-digit account ID, and region")
	}
	events := make(map[string]string)
	for _, subscription := range config.Subscriptions {
		name := strings.TrimSpace(subscription.Name)
		topLevelSource := strings.TrimSpace(subscription.Source)
		source := strings.TrimSpace(subscription.EventSource)
		if name == "" || topLevelSource == "" || source == "" || len(subscription.EventNames) == 0 {
			return nil, errors.New("AWS event subscription requires name, source, event source, and event names")
		}
		for _, eventName := range subscription.EventNames {
			eventName = strings.TrimSpace(eventName)
			if eventName == "" {
				return nil, fmt.Errorf("AWS event subscription %q contains an empty event name", name)
			}
			key := topLevelSource + "\x00" + source + "\x00" + eventName
			if existing, found := events[key]; found && existing != name {
				return nil, fmt.Errorf("AWS event %s/%s/%s belongs to both %q and %q", topLevelSource, source, eventName, existing, name)
			}
			events[key] = name
		}
	}
	if len(events) == 0 {
		return nil, errors.New("AWS event subscriber requires at least one event")
	}
	return &SQSSubscriber{client: client, queueURL: config.QueueURL, accountID: config.AccountID, region: config.Region, events: events}, nil
}

// Receive long-polls up to ten messages. Valid but unmatched events, and
// messages that fail to decode or lack CloudTrail fields, are returned for
// acknowledgement without a subscription. A malformed message is discarded
// rather than returned as an error: it can never become valid, and failing
// would stop the plugin on every redelivery. Notifications are only hints, so
// the periodic poll covers whatever change it described. A message without a
// receipt handle cannot be deleted and is skipped.
func (s *SQSSubscriber) Receive(ctx context.Context) (ChangeBatch, error) {
	output, err := s.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            &s.queueURL,
		MaxNumberOfMessages: 10,
		VisibilityTimeout:   300,
		WaitTimeSeconds:     20,
	})
	if err != nil {
		return ChangeBatch{}, fmt.Errorf("receive AWS change events: %w", err)
	}
	batch := ChangeBatch{messages: make([]queuedMessage, 0, len(output.Messages))}
	matched := make(map[string]struct{})
	for index, message := range output.Messages {
		if message.ReceiptHandle == nil || strings.TrimSpace(*message.ReceiptHandle) == "" {
			s.discard(ctx, message, index, "no receipt handle")
			continue
		}
		batch.messages = append(batch.messages, queuedMessage{receipt: *message.ReceiptHandle})
		var event cloudTrailEvent
		if err := json.Unmarshal([]byte(awsdk.ToString(message.Body)), &event); err != nil {
			// The decode error can quote the body, so it is not logged.
			s.discard(ctx, message, index, "undecodable JSON")
			continue
		}
		if event.ID == "" || event.Source == "" || event.DetailType == "" || event.Account == "" || event.Region == "" || event.Detail.EventID == "" || event.Detail.EventSource == "" || event.Detail.EventName == "" {
			s.discard(ctx, message, index, "missing required CloudTrail fields")
			continue
		}
		if event.DetailType != cloudTrailDetailType || event.Account != s.accountID || event.Region != s.region || event.Detail.ErrorCode != "" {
			continue
		}
		if name, found := s.events[event.Source+"\x00"+event.Detail.EventSource+"\x00"+event.Detail.EventName]; found {
			matched[name] = struct{}{}
		}
	}
	for name := range matched {
		batch.Subscriptions = append(batch.Subscriptions, name)
	}
	slices.Sort(batch.Subscriptions)
	return batch, nil
}

// discard logs a malformed message by its SQS message ID only; the body is
// never logged.
func (s *SQSSubscriber) discard(ctx context.Context, message types.Message, index int, reason string) {
	total := s.discarded.Add(1)
	slog.WarnContext(ctx, "discarding malformed AWS change event", "queue", s.queueURL, "message_id", awsdk.ToString(message.MessageId),
		"index", index, "reason", reason, "discarded_total", total)
}

// Discarded returns how many malformed messages were discarded.
func (s *SQSSubscriber) Discarded() uint64 { return s.discarded.Load() }

// Acknowledge deletes every message in batch, matched or not.
func (s *SQSSubscriber) Acknowledge(ctx context.Context, batch ChangeBatch) error {
	if len(batch.messages) == 0 {
		return nil
	}
	entries := make([]types.DeleteMessageBatchRequestEntry, 0, len(batch.messages))
	for index, message := range batch.messages {
		id := fmt.Sprintf("message-%d", index)
		entries = append(entries, types.DeleteMessageBatchRequestEntry{Id: &id, ReceiptHandle: &message.receipt})
	}
	output, err := s.client.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{QueueUrl: &s.queueURL, Entries: entries})
	if err != nil {
		return fmt.Errorf("acknowledge AWS change events: %w", err)
	}
	if len(output.Failed) > 0 {
		return fmt.Errorf("acknowledge AWS change events: %d of %d messages failed", len(output.Failed), len(entries))
	}
	return nil
}
