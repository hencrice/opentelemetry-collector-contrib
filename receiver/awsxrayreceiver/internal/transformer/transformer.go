// Copyright 2019, OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transformer

import (
	"encoding/json"

	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/translator/conventions"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/tracesegment"
)

// AWS X-Ray acceptable values for origin field.
const (
	originEC2 = "AWS::EC2::Instance"
	originECS = "AWS::ECS::Container"
	originEB  = "AWS::ElasticBeanstalk::Environment"
)

// the maximum possible number of attribute per X-Ray segment
// Origin,
const maxAttributeCount = 30

// ToOTSpans converts X-Ray segment to OT traces.
func ToOTSpans(rawSeg []byte) (*pdata.Traces, error) {
	var segment tracesegment.Segment
	err := json.Unmarshal(rawSeg, &segment)
	if err != nil {
		return nil, err
	}

	// example: https://github.com/open-telemetry/opentelemetry-collector/blob/e7ab219cb573242cf3a3143e78cb3819518e254d/translator/trace/jaeger/jaegerproto_to_traces.go#L36
	traceData := pdata.NewTraces()
	rss := traceData.ResourceSpans()
	rss.Resize(1)
	segToResourceSpan(&segment, rss.At(0))

	return nil, nil
}

func segToResourceSpan(segment *tracesegment.Segment, dest pdata.ResourceSpans) {
	dest.InitEmpty()
	attrs := dest.Attributes()
	attrs.InitEmptyWithCapacity(maxAttributeCount)

	addOriginToResource(segment.Origin, dest.Resource().Attributes())
	addAWSToResource(segment.AWS, dest.Resource().Attributes())
}

func addOriginToResource(origin *string, attrs pdata.AttributeMap) {
	if origin == nil || *origin == originEC2 {
		// resource will be nil and is treated by the AWS X-Ray exporter (in
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/segment.go#L253)
		// as origin == "AWS::EC2::Instance"
		return
	}

	if *origin == originEB {
		attrs.UpsertString(conventions.AttributeServiceInstance, *origin)
	} else if *origin == originECS {
		attrs.UpsertString(conventions.AttributeContainerName, *origin)
	}
}

func addAWSToResource(aws map[string]interface{}, attrs pdata.AttributeMap) {
	attrs.UpsertString(conventions.AttributeCloudProvider, "aws")

	for key, val := range aws {
		switch key {
		case "account_id":
			account, ok := val.(string)
			if ok {
				attrs.UpsertString(conventions.AttributeCloudAccount, account)
			}
		case "elastic_beanstalk":

		case "ecs":
			ecsMetadata, ok := val.(map[string]string)
			if containerName, exists := ecsMetadata["container"]; exists {
				attrs.UpsertString(conventions.AttributeContainerName, containerName)
			}
		case "ec2":
			ec2Metadata, ok := val.(map[string]string)
			if instanceID, exists := ec2Metadata["instance_id"]; exists {
				attrs.UpsertString(conventions.AttributeHostID, instanceId)
			}

			if availabilityZone, exists := ec2Metadata["availability_zone"]; exists {
				attrs.UpsertString(conventions.AttributeCloudZone, availabilityZone)
			}

			if hostType, exists := ec2Metadata["instance_size"]; exists {
				attrs.UpsertString(conventions.AttributeHostType, hostType)
			}

			if amiID, exists := ec2Metadata["ami_id"]; exists {
				attrs.UpsertString(conventions.AttributeHostImageID, amiID)
			}
		case "operation":
		case "region":
		case "request_id":
		case "queue_url":
		case "table_name":

		default:
			continue
		}
	}
}
