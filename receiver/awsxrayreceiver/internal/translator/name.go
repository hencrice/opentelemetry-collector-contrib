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
	"fmt"

	"go.opentelemetry.io/collector/consumer/pdata"

	expTrans "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/awsxrayexporter/translator"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/tracesegment"
)

const (
	validAWSNamespace    = "aws"
	validRemoteNamespace = "remote"
	awsServiceAttribute  = "aws.service"
)

func addNameAndNamespace(seg *tracesegment.Segment, span *pdata.Span) error {
	if seg.Namespace == nil {
		span.SetName(*seg.Name)
		span.SetKind(pdata.SpanKindINTERNAL)
		return nil
	}

	// https://github.com/open-telemetry/opentelemetry-specification/blob/master/specification/trace/api.md#spankind
	attrs := span.Attributes()

	// seg is a subsegment

	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/segment.go#L197
	span.SetKind(pdata.SpanKindCLIENT)
	switch *seg.Namespace {
	case validAWSNamespace:
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/segment.go#L144
		attrs.UpsertString(expTrans.AWSServiceAttribute, *seg.Name)

	case validRemoteNamespace:
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/segment.go#L193
		span.SetName(*seg.Name)
	default:
		return fmt.Errorf("unexpected namespace: %s", *seg.Namespace)
	}
	return nil
}
