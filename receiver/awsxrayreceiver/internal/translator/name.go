// Copyright The OpenTelemetry Authors
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

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/common/awsxray"
)

const (
	validAWSNamespace    = "aws"
	validRemoteNamespace = "remote"
)

func addNameAndNamespace(seg *awsxray.Segment, span *pdata.Span) error {
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/segment.go#L193
	span.SetName(*seg.Name)

	if seg.HTTP != nil && seg.HTTP.Request != nil && seg.HTTP.Request.ClientIP != nil {
		// `ClientIP` is an optional field, we only attempt to use it to set
		// a more specific spanKind if it exists.

		// The `ClientIP` is not nil, it implies that this segment is generated
		// by a server serving an incoming request
		span.SetKind(pdata.SpanKindSERVER)
	}

	if seg.Namespace == nil {
		if span.Kind() == pdata.SpanKindUNSPECIFIED {
			span.SetKind(pdata.SpanKindINTERNAL)
		}
		return nil
	}

	// seg is a subsegment

	attrs := span.Attributes()
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/segment.go#L197
	// https://github.com/open-telemetry/opentelemetry-specification/blob/master/specification/trace/api.md#spankind
	span.SetKind(pdata.SpanKindCLIENT)
	switch *seg.Namespace {
	case validAWSNamespace:
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/segment.go#L144
		attrs.UpsertString(awsxray.AWSServiceAttribute, *seg.Name)

	case validRemoteNamespace:
		// no op
	default:
		return fmt.Errorf("unexpected namespace: %s", *seg.Namespace)
	}
	return nil
}