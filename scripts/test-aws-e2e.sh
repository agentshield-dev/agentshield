#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cluster_name=agentshield-aws-e2e
namespace=agentshield-aws-e2e
region=us-east-1
account_id=000000000000
localstack_endpoint=http://localstack.${namespace}.svc.cluster.local:4566
firehose_arn=arn:aws:firehose:${region}:${account_id}:deliverystream/agentshield
firehose_access_key=agentshield-e2e
kubeconfig_path=$(mktemp)
image_context=$(mktemp -d)
port_forward_log=$(mktemp)
port_forward_pid=

cleanup() {
  status=$?
  if [[ -n "$port_forward_pid" ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
  fi
  if (( status != 0 )); then
    kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" get pods -o wide >&2 2>/dev/null || true
    kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" logs deployment/agentshield -c agentshield --tail=200 >&2 2>/dev/null || true
    kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" logs deployment/localstack --tail=200 >&2 2>/dev/null || true
    cat "$port_forward_log" >&2 2>/dev/null || true
  fi
  kind delete cluster --name "$cluster_name" >/dev/null 2>&1 || true
  rm -rf "$image_context"
  rm -f "$kubeconfig_path" "$port_forward_log"
  exit "$status"
}
trap cleanup EXIT

for command in base64 curl docker go jq kind kubectl; do
  command -v "$command" >/dev/null || { echo "required command not found: $command" >&2; exit 1; }
done

if kind get clusters | grep -Fxq "$cluster_name"; then
  kind delete cluster --name "$cluster_name"
fi

kind create cluster --name "$cluster_name" --image kindest/node:v1.34.0 --kubeconfig "$kubeconfig_path" --wait 180s

kubectl --kubeconfig "$kubeconfig_path" apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
---
apiVersion: v1
kind: Service
metadata:
  name: localstack
  namespace: $namespace
spec:
  selector:
    app: localstack
  ports:
    - name: gateway
      port: 4566
      targetPort: gateway
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: localstack
  namespace: $namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: localstack
  template:
    metadata:
      labels:
        app: localstack
    spec:
      containers:
        - name: localstack
          image: localstack/localstack:4.9.1
          env:
            - name: LOCALSTACK_HOST
              value: localstack.$namespace.svc.cluster.local:4566
            - name: SERVICES
              value: ec2,events,sqs,sts
            - name: SQS_ENDPOINT_STRATEGY
              value: path
          ports:
            - name: gateway
              containerPort: 4566
          readinessProbe:
            httpGet:
              path: /_localstack/health
              port: gateway
            periodSeconds: 2
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              memory: 1Gi
---
apiVersion: v1
kind: Secret
metadata:
  name: postgres
  namespace: $namespace
stringData:
  POSTGRES_DB: agentshield
  POSTGRES_USER: agentshield
  POSTGRES_PASSWORD: agentshield-e2e
  database-url: postgres://agentshield:agentshield-e2e@postgres.$namespace.svc.cluster.local:5432/agentshield?sslmode=disable
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: $namespace
spec:
  selector:
    app: postgres
  ports:
    - name: postgres
      port: 5432
      targetPort: postgres
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: $namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: postgres:16.10-alpine
          envFrom:
            - secretRef:
                name: postgres
          ports:
            - name: postgres
              containerPort: 5432
          readinessProbe:
            exec:
              command: [pg_isready, -U, agentshield, -d, agentshield]
            periodSeconds: 2
          resources:
            requests:
              cpu: 20m
              memory: 64Mi
            limits:
              memory: 256Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: aws-cli
  namespace: $namespace
spec:
  containers:
    - name: aws-cli
      image: amazon/aws-cli:2.31.23
      command: [sh, -c, sleep 3600]
      env:
        - name: AWS_ACCESS_KEY_ID
          value: test
        - name: AWS_SECRET_ACCESS_KEY
          value: test
        - name: AWS_DEFAULT_REGION
          value: $region
        - name: AWS_PAGER
          value: ""
EOF

kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" rollout status deployment/localstack --timeout=180s
kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" rollout status deployment/postgres --timeout=180s
kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" wait --for=condition=Ready pod/aws-cli --timeout=180s

aws_local() {
  kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" exec aws-cli -- aws --endpoint-url "$localstack_endpoint" --region "$region" "$@"
}

vpc_id=$(aws_local ec2 create-vpc --cidr-block 10.42.0.0/16 --query Vpc.VpcId --output text)
subnet_id=$(aws_local ec2 create-subnet --vpc-id "$vpc_id" --cidr-block 10.42.1.0/24 --availability-zone us-east-1a --query Subnet.SubnetId --output text)
security_group_id=$(aws_local ec2 create-security-group --vpc-id "$vpc_id" --group-name agentshield-e2e --description agentshield-e2e --query GroupId --output text)
aws_local ec2 authorize-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 443 --cidr 10.42.0.0/16 >/dev/null
network_interface_id=$(aws_local ec2 create-network-interface --subnet-id "$subnet_id" --groups "$security_group_id" --description agentshield-e2e --query NetworkInterface.NetworkInterfaceId --output text)
queue_url=$(aws_local sqs create-queue --queue-name agentshield-events --query QueueUrl --output text)
queue_arn=$(aws_local sqs get-queue-attributes --queue-url "$queue_url" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)
event_pattern=$(jq -cn '{source:["aws.ec2"],"detail-type":["AWS API Call via CloudTrail"],detail:{eventSource:["ec2.amazonaws.com"],eventName:["AuthorizeSecurityGroupIngress","DeleteNetworkInterface"]}}')
aws_local events put-rule --name agentshield-ec2-changes --event-pattern "$event_pattern" >/dev/null
aws_local events put-targets --rule agentshield-ec2-changes --targets "Id=agentshield,Arn=$queue_arn" >/dev/null

publish_change_event() {
  local event_name=$1
  local event_id=$2
  local detail entries result
  detail=$(jq -cn --arg event_id "$event_id" --arg event_name "$event_name" '{eventID:$event_id,eventSource:"ec2.amazonaws.com",eventName:$event_name}')
  entries=$(jq -cn --arg detail "$detail" '[{Source:"aws.ec2",DetailType:"AWS API Call via CloudTrail",Detail:$detail}]')
  result=$(aws_local events put-events --entries "$entries")
  jq -e '.FailedEntryCount == 0 and (.Entries | length == 1) and (.Entries[0].EventId | length > 0)' <<<"$result" >/dev/null
}

CGO_ENABLED=0 go build -o "$image_context/agentshield" "$repo_root/cmd/agentshield"
docker build --quiet --tag agentshield-aws-e2e:local --file "$repo_root/evals/config/agentshield.Dockerfile" "$image_context" >/dev/null
kind load docker-image --name "$cluster_name" agentshield-aws-e2e:local >/dev/null

kubectl --kubeconfig "$kubeconfig_path" apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: agentshield-aws
  namespace: $namespace
stringData:
  firehose-access-key: $firehose_access_key
---
apiVersion: v1
kind: Service
metadata:
  name: agentshield
  namespace: $namespace
spec:
  selector:
    app: agentshield
  ports:
    - name: http
      port: 8088
      targetPort: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentshield
  namespace: $namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agentshield
  template:
    metadata:
      labels:
        app: agentshield
    spec:
      securityContext:
        fsGroup: 65532
      initContainers:
        - name: wait-for-postgres
          image: postgres:16.10-alpine
          command: [sh, -c, until pg_isready -h postgres -U agentshield -d agentshield; do sleep 1; done]
      containers:
        - name: agentshield
          image: agentshield-aws-e2e:local
          imagePullPolicy: Never
          args:
            - --listen=0.0.0.0:8088
            - --kubernetes-disable
            - --aws-region=$region
            - --aws-events-queue-url=$queue_url
            - --aws-firehose-stream-arn=$firehose_arn
            - --telemetry-jsonl=/var/lib/agentshield/telemetry.jsonl
          env:
            - name: AGENTSHIELD_DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: postgres
                  key: database-url
            - name: AGENTSHIELD_AWS_FIREHOSE_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: agentshield-aws
                  key: firehose-access-key
            - name: AWS_ACCESS_KEY_ID
              value: test
            - name: AWS_SECRET_ACCESS_KEY
              value: test
            - name: AWS_EC2_METADATA_DISABLED
              value: "true"
            - name: AWS_ENDPOINT_URL
              value: $localstack_endpoint
          ports:
            - name: http
              containerPort: 8088
          readinessProbe:
            httpGet:
              path: /readyz
              port: http
            periodSeconds: 2
          resources:
            requests:
              cpu: 20m
              memory: 64Mi
            limits:
              memory: 256Mi
          volumeMounts:
            - name: telemetry
              mountPath: /var/lib/agentshield
        - name: telemetry-reader
          image: busybox:1.37.0
          command: [sh, -c, sleep 3600]
          volumeMounts:
            - name: telemetry
              mountPath: /var/lib/agentshield
              readOnly: true
      volumes:
        - name: telemetry
          emptyDir: {}
EOF

kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" rollout status deployment/agentshield --timeout=180s
kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" port-forward service/agentshield 18089:8088 >"$port_forward_log" 2>&1 &
port_forward_pid=$!

# /readyz only means the database is reachable; the graph routes return 503
# until discovery has published, so wait on the graph itself.
for _ in $(seq 1 60); do
  if curl --fail --silent --output /dev/null http://127.0.0.1:18089/api/v1/graph; then
    break
  fi
  sleep 1
done

graph=$(curl --fail --silent http://127.0.0.1:18089/api/v1/graph)
jq -e --arg eni "$network_interface_id" --arg sg "$security_group_id" '
  any(.snapshot.resources[]; .kind == "aws/ec2-network-interface" and any(.assertions[]; .attributes["aws/network-interface-id"] == $eni)) and
  ((.snapshot.resources[] | select(.kind == "aws/ec2-security-group" and any(.assertions[]; .attributes["aws/group-id"] == $sg)).id) as $resource_id |
    any(.snapshot.facets[]; .resourceId == $resource_id and .key == "ingress" and any(.assertions[]; .attributes["aws/rule-count"] == "1"))) and
  any(.snapshot.relationships[]; .predicate == "governed-by" and any(.assertions[]; .pluginId == "aws")) and
  any(.snapshot.resources[]; .kind == "aws/ec2-security-group" and any(.assertions[]; .attributes["aws/group-id"] == $sg))
' <<<"$graph" >/dev/null

request_id=agentshield-e2e-flow
flow_end=$(date +%s)
flow_start=$((flow_end - 60))
flow_line="5 $account_id $network_interface_id 10.42.1.10 198.51.100.10 32100 443 6 7 700 $flow_start $flow_end ACCEPT OK $vpc_id $subnet_id - 2 IPv4 10.42.1.10 198.51.100.10 $region use1-az1 egress 2"
encoded_flow=$(printf '%s\n' "$flow_line" | base64 -w0)
firehose_body=$(jq -cn --arg request_id "$request_id" --arg data "$encoded_flow" '{requestId:$request_id,records:[{data:$data}]}')
firehose_response=$(curl --fail --silent \
  -H 'Content-Type: application/json' \
  -H 'X-Amz-Firehose-Protocol-Version: 1.0' \
  -H "X-Amz-Firehose-Request-Id: $request_id" \
  -H "X-Amz-Firehose-Source-Arn: $firehose_arn" \
  -H "X-Amz-Firehose-Access-Key: $firehose_access_key" \
  --data "$firehose_body" \
  http://127.0.0.1:18089/v1/aws/firehose/vpc-flow-logs)
jq -e --arg request_id "$request_id" '.requestId == $request_id and (.errorMessage | not)' <<<"$firehose_response" >/dev/null

for _ in $(seq 1 60); do
  if kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" exec deployment/agentshield -c telemetry-reader -- cat /var/lib/agentshield/telemetry.jsonl 2>/dev/null | jq -s -e --arg eni "$network_interface_id" '
    any(.[]; .kind == "network-flow" and .pluginId == "aws" and .operation == "egress" and .outcome == "allowed" and .count == 7 and .properties["destination-port"] == "443" and (.subject.immutableKey | endswith("/network-interface/" + $eni)))
  ' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
kubectl --kubeconfig "$kubeconfig_path" -n "$namespace" exec deployment/agentshield -c telemetry-reader -- cat /var/lib/agentshield/telemetry.jsonl | jq -s -e --arg eni "$network_interface_id" '
  any(.[]; .kind == "network-flow" and .pluginId == "aws" and .operation == "egress" and .outcome == "allowed" and .count == 7 and .properties["destination-port"] == "443" and (.subject.immutableKey | endswith("/network-interface/" + $eni)))
' >/dev/null

aws_local ec2 authorize-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 8443 --cidr 10.42.0.0/16 >/dev/null
publish_change_event AuthorizeSecurityGroupIngress agentshield-e2e-sg

for _ in $(seq 1 60); do
  graph=$(curl --fail --silent http://127.0.0.1:18089/api/v1/graph)
  if jq -e --arg sg "$security_group_id" '
    (.snapshot.resources[] | select(.kind == "aws/ec2-security-group" and any(.assertions[]; .attributes["aws/group-id"] == $sg)).id) as $resource_id |
    any(.snapshot.facets[]; .resourceId == $resource_id and .key == "ingress" and any(.assertions[]; .attributes["aws/rule-count"] == "2" and (.attributes["aws/rules"] | contains("8443"))))
  ' <<<"$graph" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
jq -e --arg sg "$security_group_id" '
  (.snapshot.resources[] | select(.kind == "aws/ec2-security-group" and any(.assertions[]; .attributes["aws/group-id"] == $sg)).id) as $resource_id |
  any(.snapshot.facets[]; .resourceId == $resource_id and .key == "ingress" and any(.assertions[]; .attributes["aws/rule-count"] == "2" and (.attributes["aws/rules"] | contains("8443"))))
' <<<"$graph" >/dev/null

aws_local ec2 delete-network-interface --network-interface-id "$network_interface_id"
publish_change_event DeleteNetworkInterface agentshield-e2e-eni

for _ in $(seq 1 60); do
  graph=$(curl --fail --silent http://127.0.0.1:18089/api/v1/graph)
  if jq -e --arg eni "$network_interface_id" 'all(.snapshot.resources[]; all(.assertions[]; .attributes["aws/network-interface-id"] != $eni))' <<<"$graph" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
jq -e --arg eni "$network_interface_id" 'all(.snapshot.resources[]; all(.assertions[]; .attributes["aws/network-interface-id"] != $eni))' <<<"$graph" >/dev/null

for _ in $(seq 1 30); do
  visible=$(aws_local sqs get-queue-attributes --queue-url "$queue_url" --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible --query 'Attributes.[ApproximateNumberOfMessages,ApproximateNumberOfMessagesNotVisible]' --output text | awk '{print $1 + $2}')
  if [[ "$visible" == "0" ]]; then
    break
  fi
  sleep 1
done
[[ "$visible" == "0" ]]

printf 'AWS LocalStack end-to-end test passed\n'
