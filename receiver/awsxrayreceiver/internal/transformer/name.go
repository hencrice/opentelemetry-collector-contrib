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
	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/translator/conventions"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/awsxrayexporter/translator"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/tracesegment"
)

const (
	validAWSNamespace    = "aws"
	validRemoteNamespace = "remote"
)

func addNameAndNamespace(seg *tracesegment.Segment, attrs *pdata.AttributeMap) {
	// https://github.com/open-telemetry/opentelemetry-java-instrumentation/blob/86c438b1543dd9e56fd77bff74b24aab6f19ce72/instrumentation/aws-sdk/aws-sdk-2.2/library/src/main/java/io/opentelemetry/instrumentation/awssdk/v2_2/AwsSdkClientDecorator.java#L60
	// TODO: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/1322bef86dcb5940605e4666baccd54ba7ec2654/exporter/awsxrayexporter/translator/segment.go#L144
	// need to use the correct key name below

	if seg.Namespace != nil {
		if *seg.Namespace == validAWSNamespace {
			attrs.InsertString(translator.AWSServiceAttribute, *name)
		}
	}
	if name != nil {
		attrs.InsertString(conventions.AttributePeerService, *name)
	}
}
