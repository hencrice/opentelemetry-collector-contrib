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

package translator

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

const (
	// just a guess to avoid too many memory re-allocation
	initAttrCapacity = 30
)

// ToTraces converts X-Ray segment (and its subsegments) to OT traces.
func ToTraces(rawSeg []byte) (*pdata.Traces, error) {
	var seg tracesegment.Segment
	err := json.Unmarshal(rawSeg, &seg)
	if err != nil {
		return nil, err
	}

	err = seg.Validate()
	if err != nil {
		return nil, err
	}

	// example: https://github.com/open-telemetry/opentelemetry-collector/blob/e7ab219cb573242cf3a3143e78cb3819518e254d/translator/trace/jaeger/jaegerproto_to_traces.go#L36
	traceData := pdata.NewTraces()
	rss := traceData.ResourceSpans()
	segToResourceSpansSlice(&seg, nil, &rss)

	return &traceData, nil
}

// this function recursively appends pdata.ResourceSpans per each segment and (possibly nested) subsegments (if there's any) to the passed in pdata.ResourceSpansSlice
func segToResourceSpansSlice(seg *tracesegment.Segment, parentID *string, dest *pdata.ResourceSpansSlice) {
	// create an otlptrace.ResourceSpans for the current (sub)segment
	dest.Resize(dest.Len() + 1)   // initialize a new empty pdata.ResourceSpans
	rs := dest.At(dest.Len() - 1) // retrieve the empty pdata.ResourceSpans we just created

	// allocate a new span
	rs.InstrumentationLibrarySpans().Resize(1)
	ils := rs.InstrumentationLibrarySpans().At(0)
	ils.Spans().Resize(1)
	span := ils.Spans().At(0)

	parentID = populateSpan(seg, parentID, &span)

	resource := rs.Resource()
	populateResourceAttrs(seg, &resource)

	// For each subsegment, recursively traverse them to append more
	// otlptrace.ResourceSpans to `dest`
	for _, s := range seg.Subsegments {
		segToResourceSpansSlice(&s, parentID, dest)
	}
}

func populateSpan(seg *tracesegment.Segment, parentID *string, span *pdata.Span) {
	// allocate a new attribute map within the span created above
	attrs := span.Attributes()
	attrs.InitEmptyWithCapacity(initAttrCapacity)

	addNameAndNamespace(seg, span)
	span.SetTraceID(pdata.TraceID([]byte(*seg.TraceID)))
	span.SetID(pdata.SpanID([]byte(*seg.ID)))
	addStartTime(seg.StartTime, span)

	addEndTime(seg.EndTime, span)
	addBool(seg.InProgress, xrayInProgressAttribute, span)
	addCause(seg, span)

	if parentID != nil {
		// `seg` is an embedded subsegment. Please refer to:
		// https://docs.aws.amazon.com/xray/latest/devguide/xray-api-segmentdocuments.html#api-segmentdocuments-subsegments
		// for the difference between the embedded & independent subsegment.
		span.SetParentSpanID(*parentID)

		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/segment.go#L201
		span.SetKind(pdata.SpanKindSERVER)
	} else if seg.ParentID != nil {
		// `seg` is an independent subsegment
		span.SetParentSpanID(*seg.ParentID)

		span.SetKind(pdata.SpanKindSERVER)
	}
	// else: `seg` is the root full segment document with no parent segment.

	// return the subsegment's ID to be used as the parentID of its subsegments
	return seg.ID
}

func populateResourceAttrs(seg *tracesegment.Segment, rs *pdata.Resource) {
	// allocate a new attribute map within the Resource in the pdata.ResourceSpans allocated above
	attrs := rs.Attributes()
	attrs.InitEmptyWithCapacity(initAttrCapacity)

	addOriginField(seg.Origin, &attrs)
	addAWSField(seg.AWS, &attrs)
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