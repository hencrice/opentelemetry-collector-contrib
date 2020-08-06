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
	"io/ioutil"
	"path"
	"testing"
	"time"

	otlptrace "github.com/open-telemetry/opentelemetry-proto/gen/go/trace/v1"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/translator/conventions"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/tracesegment"
)

type perSpanProperties struct {
	traceID      string
	spanID       string
	parentSpanID *string
	name         string
	startTimeSec float64
	endTimeSec   *float64
	spanKind     pdata.SpanKind
	spanStatus   otlptrace.Status_StatusCode
	eventsProps  []eventProps
	attrs        map[string]pdata.AttributeValue
}

type eventProps struct {
	name  string
	attrs map[string]pdata.AttributeValue
}

func TestTranslation(t *testing.T) {
	tests := []struct {
		testCase              string
		samplePath            string
		expectedSegment       *tracesegment.Segment
		expectedResourceAttrs map[string]pdata.AttributeValue
		propsPerSpan          []perSpanProperties
		verification          func(testCase string,
			expectedRs *pdata.ResourceSpans,
			actualTraces *pdata.Traces,
			err error)
	}{
		{
			testCase:        "TranslateInstrumentedServerSegment",
			samplePath:      path.Join("../../", "testdata", "rawsegment", "serverSample.txt"),
			expectedSegment: &tracesegment.RawExpectedSegmentForInstrumentedServer,
			expectedResourceAttrs: func(seg *tracesegment.Segment) map[string]pdata.AttributeValue {
				return nil
			}(&tracesegment.RawExpectedSegmentForInstrumentedServer),
			propsPerSpan: func(seg *tracesegment.Segment) []perSpanProperties {
				props := make(map[string]pdata.AttributeValue)
				props[conventions.AttributeHTTPMethod] = pdata.NewAttributeValueString(
					*seg.HTTP.Request.Method)
				props[conventions.AttributeHTTPClientIP] = pdata.NewAttributeValueString(
					*seg.HTTP.Request.ClientIP)
				props[conventions.AttributeHTTPUserAgent] = pdata.NewAttributeValueString(
					*seg.HTTP.Request.UserAgent)
				props[AWSXRayXForwardedForAttribute] = pdata.NewAttributeValueBool(
					*seg.HTTP.Request.XForwardedFor)
				props[conventions.AttributeHTTPStatusCode] = pdata.NewAttributeValueInt(
					*seg.HTTP.Response.Status)
				props[conventions.AttributeHTTPURL] = pdata.NewAttributeValueString(
					*seg.HTTP.Request.URL)

				res := perSpanProperties{
					traceID:      *seg.TraceID,
					spanID:       *seg.ID,
					name:         *seg.Name,
					startTimeSec: *seg.StartTime,
					endTimeSec:   seg.EndTime,
					spanKind:     pdata.SpanKindSERVER,
					spanStatus:   otlptrace.Status_Ok,
					attrs:        props,
				}
				return []perSpanProperties{res}
			}(&tracesegment.RawExpectedSegmentForInstrumentedServer),
			verification: func(testCase string,
				expectedRs *pdata.ResourceSpans, actualTraces *pdata.Traces, err error) {
				assert.NoError(t, err, testCase+": translation should've succeeded")
				assert.Equal(t, actualTraces.ResourceSpans().Len(), 1,
					"one segment should translate to 1 ResourceSpans")

				actualRs := actualTraces.ResourceSpans().At(0)
				assert.Equal(t, *expectedRs, actualRs,
					testCase+": actual ResourceSpans differ from the expected")
			},
		},
		{
			testCase:        "TranslateInstrumentedClientSegment",
			samplePath:      path.Join("../../", "testdata", "rawsegment", "ddbSample.txt"),
			expectedSegment: &tracesegment.RawExpectedSegmentForInstrumentedApp,
			expectedResourceAttrs: func() map[string]pdata.AttributeValue {
				return nil
			}(),
			propsPerSpan: func() []perSpanProperties {
				return nil
			}(),
			verification: func(testCase string,
				expectedRs *pdata.ResourceSpans, actualTraces *pdata.Traces, err error) {
				assert.NoError(t, err, testCase+": translation should've succeeded")
				assert.Equal(t, actualTraces.ResourceSpans().Len(), 1,
					"one segment should translate to 1 ResourceSpans")
			},
		},
	}

	for _, tc := range tests {
		expectedRs := initResourceSpans(
			tc.expectedSegment,
			tc.expectedResourceAttrs,
			tc.propsPerSpan,
		)

		content, err := ioutil.ReadFile(tc.samplePath)
		assert.NoError(t, err, fmt.Sprintf("[%s] can not read raw segment", tc.testCase))

		_, body, err := tracesegment.SplitHeaderBody(content)
		assert.NoError(t, err, fmt.Sprintf("[%s] can split body", tc.testCase))
		assert.True(t, len(body) > 0, fmt.Sprintf("[%s] body length is 0", tc.testCase))

		traces, err := ToTraces(body)
		tc.verification(tc.testCase, expectedRs, traces, err)
	}
}

func initResourceSpans(expectedSeg *tracesegment.Segment,
	resourceAttrs map[string]pdata.AttributeValue,
	propsPerSpan []perSpanProperties,
) *pdata.ResourceSpans {
	if expectedSeg == nil {
		return nil
	}

	rs := pdata.NewResourceSpans()
	rs.InitEmpty()
	rs.Resource().InitEmpty()
	resourceAttrMap := pdata.NewAttributeMap()
	resourceAttrMap.InitFromMap(resourceAttrs)
	rs.Resource().Attributes().InitFromAttributeMap(resourceAttrMap)
	rs.InstrumentationLibrarySpans().Resize(1)
	ls := rs.InstrumentationLibrarySpans().At(0)
	ls.InitEmpty()
	ls.InstrumentationLibrary().InitEmpty()
	ls.InstrumentationLibrary().SetName(
		*expectedSeg.AWS.XRay.SDK)
	ls.InstrumentationLibrary().SetVersion(
		*expectedSeg.AWS.XRay.SDKVersion)
	ls.Spans().Resize(len(propsPerSpan))

	for i, props := range propsPerSpan {
		sp := ls.Spans().At(i)
		sp.Attributes().Insert
		sp.SetSpanID(pdata.SpanID([]byte(props.spanID)))
		if props.parentSpanID != nil {
			sp.SetParentSpanID(pdata.SpanID([]byte(*props.parentSpanID)))
		}
		sp.SetName(props.name)
		sp.SetStartTime(pdata.TimestampUnixNano(props.startTimeSec * float64(time.Second)))
		if props.endTimeSec != nil {
			sp.SetEndTime(pdata.TimestampUnixNano(*props.endTimeSec * float64(time.Second)))
		}
		sp.SetKind(props.spanKind)
		sp.SetTraceID(pdata.TraceID([]byte(props.traceID)))
		if props.spanStatus != nil {
			sp.Status().InitEmpty()
			sp.Status().SetCode(pdata.StatusCode(*props.spanStatus))
		}

		sp.Events().Resize(len(props.eventsProps))
		for i, evtProps := range props.eventsProps {
			spEvt := sp.Events().At(i)
			spEvt.SetName(evtProps.name)
			evtAttrMap := pdata.NewAttributeMap()
			evtAttrMap.InitFromMap(evtProps.attrs)
			spEvt.Attributes().InitFromAttributeMap(evtAttrMap)
		}

		spanAttrMap := pdata.NewAttributeMap()
		spanAttrMap.InitFromMap(props.attrs)
		sp.Attributes().InitFromAttributeMap(spanAttrMap)
	}
	return &rs
}
