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
	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/translator/conventions"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/tracesegment"
)

func addHTTPAndCause(seg *tracesegment.Segment, span *pdata.Span) {
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/http.go#L47
	attrs := span.Attributes()
	if req := seg.HTTP.Request; req != nil {
		if req.Method != nil {
			attrs.UpsertString(conventions.AttributeHTTPMethod, *req.Method)
		}

		if req.ClientIP != nil {
			attrs.UpsertString(conventions.AttributeHTTPClientIP, *req.ClientIP)
			span.SetKind(pdata.SpanKindSERVER)
		}

		if req.UserAgent != nil {
			attrs.UpsertString(conventions.AttributeHTTPUserAgent, *req.UserAgent)
		}

		if req.URL != nil {
			attrs.UpsertString(conventions.AttributeHTTPURL, *req.URL)
		}
	}

	if resp := seg.HTTP.Response; resp != nil {
		if resp.Status != nil && resp.ContentLength != nil {
			attrs.UpsertInt(conventions.AttributeHTTPStatusCode, int64(*resp.Status))
			attrs.UpsertInt(conventions.AttributeHTTPResponseContentLength, int64(*resp.ContentLength))
			if (*resp.Status < 200 || *resp.Status > 299) && seg.Cause != nil {
				addCause(seg, span)
			}
		}
	}

	return
}

func addCause(seg *tracesegment.Segment, span *pdata.Span) {
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/cause.go#L48
	switch seg.Cause.Type {
	case tracesegment.CauseTypeExceptionID:
		// Right now the X-Ray exporter always genearate a new ID:
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/cause.go#L74
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/cause.go#L112
		// so we can only pass this as part of the status message as a fallback mechanism
		span.Status().InitEmpty()
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
				attrs.InsertString(conventions.AttributeExceptionType, *excp.Type)
				attrs.InsertString(conventions.AttributeExceptionMessage, *excp.Message)
				// For now the stack in the exception is not set via
				// conventions.AttributeExceptionStacktrace
			}
		}
	}
}
