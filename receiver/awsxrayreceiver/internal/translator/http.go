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
	"strconv"
	"strings"

	otlptrace "github.com/open-telemetry/opentelemetry-proto/gen/go/trace/v1"
	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/translator/conventions"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/tracesegment"
)

const (
	newLine   = "\n"
	separator = ":"
)

func addHTTPAndCause(seg *tracesegment.Segment, span *pdata.Span) {
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/http.go#L47
	attrs := span.Attributes()
	if seg.HTTP != nil {
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
			if resp.Status != nil && resp.ContentLength != nil {
				span.Status().InitEmpty()
				otStatus := httpStatusToOTStatus(*resp.Status)
				// in X-Ray exporter, the segment status is set via
				// span attributes, the status code here is not
				// actually used
				span.Status().SetCode(pdata.StatusCode(otStatus))
				attrs.UpsertInt(conventions.AttributeHTTPStatusCode, int64(*resp.Status))
				attrs.UpsertInt(conventions.AttributeHTTPResponseContentLength, int64(*resp.ContentLength))
				if otStatus != otlptrace.Status_Ok && seg.Cause != nil {
					addCause(seg, span)
				}
			}
		}
	}

	return
}

var statusMap = map[int]otlptrace.Status_StatusCode{
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

func addCause(seg *tracesegment.Segment, span *pdata.Span) {
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/cause.go#L48
	switch seg.Cause.Type {
	case tracesegment.CauseTypeExceptionID:
		// Right now the X-Ray exporter always genearate a new ID:
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/cause.go#L74
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/cause.go#L112
		// so we can only pass this as part of the status message as a fallback mechanism
		span.Status().SetMessage(*seg.Cause.ExceptionID)
	case tracesegment.CauseTypeObject:
		evts := span.Events()
		exceptionEventStartIndex := evts.Len()
		evts.Resize(exceptionEventStartIndex + len(seg.Cause.Exceptions))

		for i, excp := range seg.Cause.Exceptions {
			evt := evts.At(exceptionEventStartIndex + i)
			evt.InitEmpty()
			evt.SetName(conventions.AttributeExceptionEventName)
			attrs := evt.Attributes()
			attrs.InitEmptyWithCapacity(2)
			if excp.Type != nil {
				attrs.UpsertString(conventions.AttributeExceptionType, *excp.Type)
				attrs.UpsertString(conventions.AttributeExceptionMessage, *excp.Message)
				stackTrace := convertStackFramesToStackTraceStr(excp.Stack)
				attrs.UpsertString(conventions.AttributeExceptionStacktrace, stackTrace)
				// For now X-Ray's exception data model is not fully supported in the OpenTelemetry
				// spec, so some information is lost here.
				// For example, the "cause" ,"remote", ... and some fields within each exception
				// are dropped.
			}
		}
	}
}

func convertStackFramesToStackTraceStr(stack []tracesegment.StackFrame) string {
	var b strings.Builder
	for _, frame := range stack {
		line := strconv.Itoa(*frame.Line)
		// the string representation of a frame looks like:
		// <*frame.Label>\n<*frame.Path>:line\n
		b.Grow(len(*frame.Label) + len(*frame.Path) + len(line) + 3)
		b.WriteString(*frame.Label)
		b.WriteString(newLine)
		b.WriteString(*frame.Path)
		b.WriteString(separator)
		b.WriteString(line)
		b.WriteString(newLine)
	}
	return b.String()
}
