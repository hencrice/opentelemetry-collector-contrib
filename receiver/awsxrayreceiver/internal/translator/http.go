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
	otlptrace "github.com/open-telemetry/opentelemetry-proto/gen/go/trace/v1"
	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/translator/conventions"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/tracesegment"
)

func addHTTP(seg *tracesegment.Segment, span *pdata.Span) {
	span.Status().InitEmpty()
	if seg.HTTP == nil {
		return
	}

	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/http.go#L47
	attrs := span.Attributes()

	if req := seg.HTTP.Request; req != nil {
		// https://docs.aws.amazon.com/xray/latest/devguide/xray-api-segmentdocuments.html#api-segmentdocuments-http
		addString(req.Method, conventions.AttributeHTTPMethod, &attrs)

		if req.ClientIP != nil {
			// since the ClientIP is not nil, this means that this segment is generated
			// by a server serving an incoming request
			attrs.UpsertString(conventions.AttributeHTTPClientIP, *req.ClientIP)
			span.SetKind(pdata.SpanKindSERVER)
		}

		addString(req.UserAgent, conventions.AttributeHTTPUserAgent, &attrs)
		addString(req.URL, conventions.AttributeHTTPURL, &attrs)
		addBool(req.XForwardedFor, AWSXRayXForwardedForAttribute, &attrs)
	}

	if resp := seg.HTTP.Response; resp != nil {
		if resp.Status != nil {
			otStatus := httpStatusToOTStatus(*resp.Status)
			// in X-Ray exporter, the segment status is set via
			// span attributes, the status code here is not
			// actually used
			span.Status().SetCode(pdata.StatusCode(otStatus))
			attrs.UpsertInt(conventions.AttributeHTTPStatusCode, int64(*resp.Status))
		}

		addInt(resp.ContentLength, conventions.AttributeHTTPResponseContentLength, &attrs)
	}

}

var statusMap = map[int]otlptrace.Status_StatusCode{
	200: otlptrace.Status_Ok,
	400: otlptrace.Status_InvalidArgument,
	401: otlptrace.Status_Unauthenticated,
	403: otlptrace.Status_PermissionDenied,
	404: otlptrace.Status_NotFound,
	408: otlptrace.Status_DeadlineExceeded,
	409: otlptrace.Status_AlreadyExists,
	412: otlptrace.Status_FailedPrecondition,
	416: otlptrace.Status_OutOfRange,
	429: otlptrace.Status_ResourceExhausted,
	500: otlptrace.Status_InternalError,
	501: otlptrace.Status_Unimplemented,
	503: otlptrace.Status_Unavailable,
}

func httpStatusToOTStatus(s int) otlptrace.Status_StatusCode {
	// references:
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
	// https://github.com/grpc/grpc/blob/master/doc/statuscodes.md

	// these otlp status are not mapped:
	// Status_Cancelled
	// Status_Aborted
	// Status_DataLoss

	c, found := statusMap[s]
	if found {
		return c
	}
	if s > 200 || s < 300 {
		return otlptrace.Status_Ok
	} else if s > 400 && s < 500 {
		return otlptrace.Status_InvalidArgument
	} else if s > 500 && s < 600 {
		return otlptrace.Status_InternalError
	}

	return otlptrace.Status_UnknownError
}
