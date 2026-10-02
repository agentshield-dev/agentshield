package aws

import (
	"context"
	"strings"
	"testing"

	awsdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func TestSQSSubscriberMatchesAndAcknowledgesCloudTrailEvents(t *testing.T) {
	client := &fakeSQS{messages: []types.Message{
		{MessageId: awsdk.String("known"), ReceiptHandle: awsdk.String("receipt-1"), Body: awsdk.String(cloudTrailEventBody("ModifyNetworkInterfaceAttribute", ""))},
		{MessageId: awsdk.String("failed"), ReceiptHandle: awsdk.String("receipt-2"), Body: awsdk.String(cloudTrailEventBody("DeleteSecurityGroup", "Client.UnauthorizedOperation"))},
	}}
	subscriber, err := NewSQSSubscriber(client, SQSSubscriberConfig{
		QueueURL: "https://sqs.us-east-1.amazonaws.com/111111111111/agentshield", AccountID: "111111111111", Region: "us-east-1",
		Subscriptions: InventoryEventSubscriptions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := subscriber.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Subscriptions) != 1 || batch.Subscriptions[0] != "network-interfaces" {
		t.Fatalf("subscriptions = %v", batch.Subscriptions)
	}
	if client.receive.MaxNumberOfMessages != 10 || client.receive.WaitTimeSeconds != 20 || client.receive.VisibilityTimeout != 300 {
		t.Fatalf("receive options = %#v", client.receive)
	}
	if err := subscriber.Acknowledge(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if client.deleted == nil || len(client.deleted.Entries) != 2 {
		t.Fatalf("deleted entries = %#v", client.deleted)
	}
}

func TestSQSSubscriberDiscardsMalformedEvents(t *testing.T) {
	client := &fakeSQS{messages: []types.Message{
		{MessageId: awsdk.String("fields"), ReceiptHandle: awsdk.String("receipt-1"), Body: awsdk.String(`{"source":"aws.ec2"}`)},
		{MessageId: awsdk.String("json"), ReceiptHandle: awsdk.String("receipt-2"), Body: awsdk.String(`not json`)},
		{MessageId: awsdk.String("receipt"), Body: awsdk.String(cloudTrailEventBody("DeleteSecurityGroup", ""))},
		{MessageId: awsdk.String("valid"), ReceiptHandle: awsdk.String("receipt-3"), Body: awsdk.String(cloudTrailEventBody("DeleteSecurityGroup", ""))},
	}}
	subscriber, err := NewSQSSubscriber(client, SQSSubscriberConfig{
		QueueURL: "queue", AccountID: "111111111111", Region: "us-east-1", Subscriptions: InventoryEventSubscriptions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := subscriber.Receive(context.Background())
	if err != nil {
		t.Fatalf("Receive error = %v", err)
	}
	if len(batch.Subscriptions) != 1 || batch.Subscriptions[0] != "security-groups" {
		t.Fatalf("subscriptions = %v", batch.Subscriptions)
	}
	if got := subscriber.Discarded(); got != 3 {
		t.Fatalf("discarded = %d, want 3", got)
	}
	if err := subscriber.Acknowledge(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	var receipts []string
	for _, entry := range client.deleted.Entries {
		receipts = append(receipts, awsdk.ToString(entry.ReceiptHandle))
	}
	if strings.Join(receipts, ",") != "receipt-1,receipt-2,receipt-3" {
		t.Fatalf("deleted receipts = %v", receipts)
	}
}

func cloudTrailEventBody(eventName, errorCode string) string {
	return `{"id":"eventbridge-id","source":"aws.ec2","detail-type":"AWS API Call via CloudTrail","account":"111111111111","region":"us-east-1","detail":{"eventID":"cloudtrail-id","eventSource":"ec2.amazonaws.com","eventName":"` + eventName + `","errorCode":"` + errorCode + `"}}`
}

type fakeSQS struct {
	messages []types.Message
	receive  *sqs.ReceiveMessageInput
	deleted  *sqs.DeleteMessageBatchInput
}

func (f *fakeSQS) ReceiveMessage(_ context.Context, input *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	f.receive = input
	return &sqs.ReceiveMessageOutput{Messages: f.messages}, nil
}

func (f *fakeSQS) DeleteMessageBatch(_ context.Context, input *sqs.DeleteMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
	f.deleted = input
	return &sqs.DeleteMessageBatchOutput{}, nil
}
