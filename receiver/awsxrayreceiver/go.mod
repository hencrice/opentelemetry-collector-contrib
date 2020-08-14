module github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver

go 1.14

require (
	github.com/aws/aws-sdk-go v1.34.1
	github.com/aws/aws-xray-daemon v3.0.1+incompatible
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/google/uuid v1.1.1
	github.com/prometheus/common v0.11.1
	github.com/stretchr/testify v1.6.1
	go.opentelemetry.io/collector v0.8.0
	go.uber.org/zap v1.15.0
	golang.org/x/net v0.0.0-20200625001655-4c5254603344
)
