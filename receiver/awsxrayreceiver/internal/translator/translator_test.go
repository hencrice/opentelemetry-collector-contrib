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
		expectedResourceAttrs func(seg *tracesegment.Segment) map[string]pdata.AttributeValue
		propsPerSpan          func(seg *tracesegment.Segment) []perSpanProperties
		verification          func(testCase string,
			expectedRs *pdata.ResourceSpans,
			actualTraces *pdata.Traces,
			err error)
	}{
		{
			testCase:   "TranslateInstrumentedServerSegment",
			samplePath: path.Join("../../", "testdata", "rawsegment", "serverSample.txt"),
			expectedResourceAttrs: func(seg *tracesegment.Segment) map[string]pdata.AttributeValue {
				attrs := make(map[string]pdata.AttributeValue)
				attrs[conventions.AttributeCloudProvider] = pdata.NewAttributeValueString("aws")
				return attrs
			},
			propsPerSpan: func(seg *tracesegment.Segment) []perSpanProperties {
				attrs := make(map[string]pdata.AttributeValue)
				attrs[conventions.AttributeHTTPMethod] = pdata.NewAttributeValueString(
					*seg.HTTP.Request.Method)
				attrs[conventions.AttributeHTTPClientIP] = pdata.NewAttributeValueString(
					*seg.HTTP.Request.ClientIP)
				attrs[conventions.AttributeHTTPUserAgent] = pdata.NewAttributeValueString(
					*seg.HTTP.Request.UserAgent)
				attrs[AWSXRayXForwardedForAttribute] = pdata.NewAttributeValueBool(
					*seg.HTTP.Request.XForwardedFor)
				attrs[conventions.AttributeHTTPStatusCode] = pdata.NewAttributeValueInt(
					int64(*seg.HTTP.Response.Status))
				attrs[conventions.AttributeHTTPURL] = pdata.NewAttributeValueString(
					*seg.HTTP.Request.URL)

				res := perSpanProperties{
					traceID:      *seg.TraceID,
					spanID:       *seg.ID,
					name:         *seg.Name,
					startTimeSec: *seg.StartTime,
					endTimeSec:   seg.EndTime,
					spanKind:     pdata.SpanKindSERVER,
					spanStatus:   otlptrace.Status_Ok,
					attrs:        attrs,
				}
				return []perSpanProperties{res}
			},
			verification: func(testCase string,
				expectedRs *pdata.ResourceSpans, actualTraces *pdata.Traces, err error) {
				assert.NoError(t, err, testCase+": translation should've succeeded")
				assert.Equal(t, 1, actualTraces.ResourceSpans().Len(),
					testCase+": one segment should translate to 1 ResourceSpans")

				actualRs := actualTraces.ResourceSpans().At(0)
				compare2ResourceSpans(t, testCase, expectedRs, &actualRs)
			},
		},
		// {
		// 	testCase:   "TranslateInstrumentedClientSegment",
		// 	samplePath: path.Join("../../", "testdata", "rawsegment", "ddbSample.txt"),
		// 	expectedResourceAttrs: func(seg *tracesegment.Segment) map[string]pdata.AttributeValue {
		// 		attrs := make(map[string]pdata.AttributeValue)
		// 		attrs[conventions.AttributeCloudProvider] = pdata.NewAttributeValueString("aws")

		// 		return attrs
		// 	},
		// 	propsPerSpan: func(seg *tracesegment.Segment) []perSpanProperties {
		// 		rootSpanAttrs := make(map[string]pdata.AttributeValue)
		// 		rootSpanAttrs[] = pdata.NewAttributeValueString()
		// 		rootSpan := perSpanProperties{
		// 			traceID:      *seg.TraceID,
		// 			spanID:       *seg.ID,
		// 			name:         *seg.Name,
		// 			startTimeSec: *seg.StartTime,
		// 			endTimeSec:   seg.EndTime,
		// 			spanKind:     pdata.SpanKindInternal,
		// 			// TODO: the span status does not seem to be correct
		// 			spanStatus:   otlptrace.Status_OutOfRange,
		// 			attrs:        rootSpanAttrs,
		// 		}

		// 		return []perSpanProperties{res}
		// 	},
		// 	verification: func(testCase string,
		// 		expectedRs *pdata.ResourceSpans, actualTraces *pdata.Traces, err error) {
		// 		assert.NoError(t, err, testCase+": translation should've succeeded")
		// 		assert.Equal(t, 1, actualTraces.ResourceSpans().Len(),
		// 			"one segment should translate to 1 ResourceSpans")

		// 		actualRs := actualTraces.ResourceSpans().At(0)
		// 		compare2ResourceSpans(t, testCase, expectedRs, &actualRs)
		// 	},
		// },
	}

	for _, tc := range tests {
		content, err := ioutil.ReadFile(tc.samplePath)
		assert.NoError(t, err, tc.testCase+": can not read raw segment")

		_, body, err := tracesegment.SplitHeaderBody(content)
		assert.NoError(t, err, tc.testCase+": can split body")
		assert.True(t, len(body) > 0, tc.testCase+": body length is 0")

		var actualSeg tracesegment.Segment
		err = json.Unmarshal(body, &actualSeg)
		// the correctness of the actual segment
		// has been verified in the tracesegment_test.go
		assert.NoError(t, err, tc.testCase+": failed to unmarhal raw segment")

		expectedRs := initResourceSpans(
			&actualSeg,
			tc.expectedResourceAttrs(&actualSeg),
			tc.propsPerSpan(&actualSeg),
		)

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
		sp.Status().InitEmpty()
		sp.Status().SetCode(pdata.StatusCode(props.spanStatus))

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

// note that this function causes side effects on the expected (
// abbrev. as exp) and actual ResourceSpans (abbrev. as act):
// 1. clears the resource attributes on both exp and act, after verifying
// .  both sets are the same.
// 2. clears the span attributes of all the
//    spans on both exp and act, after going through all the spans
// .  on both exp and act and verify that all the attributes match.
// 3. similarly, for all the events and their attributes within a span,
//    this function performs the same equality verification, then clears
//    up all the attribute.
// The reason for doing so is just to be able to use deep equal via assert.Equal()
func compare2ResourceSpans(t *testing.T, testCase string, exp, act *pdata.ResourceSpans) {
	assert.Equal(t, exp.InstrumentationLibrarySpans().Len(),
		act.InstrumentationLibrarySpans().Len(),
		testCase+": InstrumentationLibrarySpans.Len() differ")

	assert.Equal(t,
		exp.Resource().Attributes().Sort(),
		act.Resource().Attributes().Sort(),
		testCase+": Resource.Attributes() differ")
	exp.Resource().InitEmpty()
	act.Resource().InitEmpty()

	actSpans := act.InstrumentationLibrarySpans().At(0).Spans()
	expSpans := exp.InstrumentationLibrarySpans().At(0).Spans()
	assert.Equal(t,
		expSpans.Len(),
		actSpans.Len(),
		testCase+": span.Len() differ",
	)

	for i := 0; i < expSpans.Len(); i++ {
		expS := expSpans.At(i)
		actS := actSpans.At(i)

		assert.Equal(t,
			expS.Attributes().Sort(),
			actS.Attributes().Sort(),
			fmt.Sprintf("%s: span%d.Attributes() differ", testCase, i),
		)
		expS.Attributes().InitEmptyWithCapacity(0)
		actS.Attributes().InitEmptyWithCapacity(0)

		expEvts := expS.Events()
		actEvts := actS.Events()
		assert.Equal(t,
			expEvts.Len(),
			actEvts.Len(),
			fmt.Sprintf("%s: span%d.Events().Len() differ",
				testCase, i),
		)

		for j := 0; j < expEvts.Len(); j++ {
			expEvt := expEvts.At(j)
			actEvt := actEvts.At(j)

			assert.Equal(t,
				expEvt.Attributes().Sort(),
				actEvt.Attributes().Sort(),
				fmt.Sprintf("%s: span%d, event%d.Attributes() differ",
					testCase, i, j),
			)
			expEvt.Attributes().InitEmptyWithCapacity(0)
			actEvt.Attributes().InitEmptyWithCapacity(0)
		}
	}

	assert.Equal(t, exp, act,
		testCase+": actual ResourceSpans differ from the expected")
}
