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

package tracesegment

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/util"
)

func TestTraceSegmentHeaderIsValid(t *testing.T) {
	header := Header{
		Format:  "json",
		Version: 1,
	}

	valid := header.IsValid()

	assert.True(t, valid)
}

func TestTraceSegmentHeaderIsValidCaseInsensitive(t *testing.T) {
	header := Header{
		Format:  "jSoN",
		Version: 1,
	}

	valid := header.IsValid()

	assert.True(t, valid)
}

func TestTraceSegmentHeaderIsValidWrongVersion(t *testing.T) {
	header := Header{
		Format:  "json",
		Version: 2,
	}

	valid := header.IsValid()

	assert.False(t, valid)
}

func TestTraceSegmentHeaderIsValidWrongFormat(t *testing.T) {
	header := Header{
		Format:  "xml",
		Version: 1,
	}

	valid := header.IsValid()

	assert.False(t, valid)
}

func TestTraceSegmentHeaderIsValidWrongFormatVersion(t *testing.T) {
	header := Header{
		Format:  "xml",
		Version: 2,
	}

	valid := header.IsValid()

	assert.False(t, valid)
}

func TestTraceBodyCorrectlyUnmarshalled(t *testing.T) {
	content, err := ioutil.ReadFile(path.Join("../../", "testdata", "rawsegment", "ddbResourceNotFoundError.txt"))
	assert.NoError(t, err, "can not read raw segment")

	splitBuf := make([][]byte, 2)
	separator := []byte(util.ProtocolSeparator)
	slices := util.SplitHeaderBody(zap.NewNop(), &content, &separator, &splitBuf)
	assert.True(t, len(slices[1]) > 0, "body length is 0")

	var actualSeg Segment
	err = json.Unmarshal(slices[1], &actualSeg)
	assert.NoError(t, err, "can not unmarshall body")

	assert.Equal(t, Segment{
		Name:      aws.String("DDB.TableDoesNotExist"),
		ID:        aws.String("5cc4a447f5d4d696"),
		StartTime: aws.Float64(1595437651.680097),
		TraceID:   aws.String("1-5f187253-6a106696d56b1f4ef9eba2ed"),
		EndTime:   aws.Float64(1595437652.197392),
		// InProgress: nil,
		Fault: aws.Bool(true),
		// Error: nil
		// Throttle: nil
		User: aws.String("xraysegmentdump"),
		// ResourceARN: nil
		// Origin: nil
		// ParentID: nil
		Cause: &CauseData{
			Type: CauseTypeObject,
			// ExceptionID: nil
			causeObject: causeObject{
				WorkingDirectory: aws.String("/Users/yenlinc/workplace/yenlinc/opentelemetry-collector-contrib/receiver/awsxrayreceiver/testdata/rawsegment/sampleapp"),
				// Paths: nil
				Exceptions: []Exception{
					{
						ID:      aws.String("8be1894c802a70c7"),
						Message: aws.String("ResourceNotFoundException: Requested resource not found: Table: does_not_exist not found"),
						Type:    aws.String("dynamodb.ResourceNotFoundException"),
						Remote:  aws.Bool(true),
						// Truncated: nil
						// Skipped: nil
						// Cause: nil
						Stack: []StackFrame{
							{
								Path:  aws.String("runtime/proc.go"),
								Line:  aws.Int(203),
								Label: aws.String("main"),
							},
							{
								Path:  aws.String("runtime/asm_amd64.s"),
								Line:  aws.Int(1373),
								Label: aws.String("goexit"),
							},
						},
					},
				},
			},
		},
		Annotations: map[string]interface{}{
			"DDB.TableDoesNotExist.DescribeTable.Annotation": "anno",
		},
		Metadata: map[string]map[string]interface{}{
			"default": map[string]interface{}{
				"DDB.TableDoesNotExist.DescribeTable.AddMetadata": "meta",
			},
		},
		// Type: nil
		Subsegments: []Segment{
			{
				Name:      aws.String("DDB.TableDoesNotExist.DescribeTable"),
				ID:        aws.String("1be15bb9b8ddfb71"),
				StartTime: aws.Float64(1595437651.683031),
				// TraceID: nil
				EndTime: aws.Float64(1595437652.197367),
				// InProgress: nil
				Fault: aws.Bool(true),
				Cause: &CauseData{
					Type: CauseTypeObject,
					// ExceptionID: nil
					causeObject: causeObject{
						WorkingDirectory: aws.String("/Users/yenlinc/workplace/yenlinc/opentelemetry-collector-contrib/receiver/awsxrayreceiver/testdata/rawsegment/sampleapp"),
						// Paths: nil
						Exceptions: []Exception{
							{
								ID:      aws.String("aef48bafb51c6326"),
								Message: aws.String("ResourceNotFoundException: Requested resource not found: Table: does_not_exist not found"),
								Type:    aws.String("dynamodb.ResourceNotFoundException"),
								Remote:  aws.Bool(true),
								// Truncated: nil
								// Skipped: nil
								// Cause: nil
								Stack: []StackFrame{
									{
										Path:  aws.String("github.com/aws/aws-xray-sdk-go@v1.1.0/xray/capture.go"),
										Line:  aws.Int(48),
										Label: aws.String("Capture"),
									},
									{
										Path:  aws.String("sampleapp/sample.go"),
										Line:  aws.Int(30),
										Label: aws.String("ddbExpectedFailure"),
									},
									{
										Path:  aws.String("sampleapp/sample.go"),
										Line:  aws.Int(25),
										Label: aws.String("main"),
									},
									{
										Path:  aws.String("runtime/proc.go"),
										Line:  aws.Int(203),
										Label: aws.String("main"),
									},
									{
										Path:  aws.String("runtime/asm_amd64.s"),
										Line:  aws.Int(1373),
										Label: aws.String("goexit"),
									},
								},
							},
						},
					},
				},
			},
			{
				Name:      aws.String("dynamodb"),
				ID:        aws.String("56005e918f9d1622"),
				StartTime: aws.Float64(1595437651.6859698),
				// TraceID: nil
				EndTime: aws.Float64(1595437652.1973178),
				// InProgress: nil
				Fault: aws.Bool(true),
				Cause: &CauseData{
					Type: CauseTypeObject,
					// ExceptionID: nil
					causeObject: causeObject{
						WorkingDirectory: aws.String("/Users/yenlinc/workplace/yenlinc/opentelemetry-collector-contrib/receiver/awsxrayreceiver/testdata/rawsegment/sampleapp"),
						// Paths: nil
						Exceptions: []Exception{
							{
								ID:      aws.String("cfc1a356a0d6f70d"),
								Message: aws.String("ResourceNotFoundException: Requested resource not found: Table: does_not_exist not found"),
								Type:    aws.String("dynamodb.ResourceNotFoundException"),
								Remote:  aws.Bool(true),
								// Truncated: nil
								// Skipped: nil
								// Cause: nil
								Stack: []StackFrame{
									{
										Path:  aws.String("github.com/aws/aws-sdk-go@v1.33.9/aws/request/handlers.go"),
										Line:  aws.Int(267),
										Label: aws.String("(*HandlerList).Run"),
									},
									{
										Path:  aws.String("github.com/aws/aws-sdk-go@v1.33.9/aws/request/request.go"),
										Line:  aws.Int(515),
										Label: aws.String("(*Request).Send.func1"),
									},
									{
										Path:  aws.String("github.com/aws/aws-sdk-go@v1.33.9/aws/request/request.go"),
										Line:  aws.Int(538),
										Label: aws.String("(*Request).Send"),
									},
									{
										Path:  aws.String("github.com/aws/aws-sdk-go@v1.33.9/service/dynamodb/api.go"),
										Line:  aws.Int(2275),
										Label: aws.String("(*DynamoDB).DescribeTableWithContext"),
									},
									{
										Path:  aws.String("sampleapp/sample.go"),
										Line:  aws.Int(31),
										Label: aws.String("ddbExpectedFailure.func1"),
									},
									{
										Path:  aws.String("github.com/aws/aws-xray-sdk-go@v1.1.0/xray/capture.go"),
										Line:  aws.Int(45),
										Label: aws.String("Capture"),
									},
									{
										Path:  aws.String("sampleapp/sample.go"),
										Line:  aws.Int(30),
										Label: aws.String("ddbExpectedFailure"),
									},
									{
										Path:  aws.String("sampleapp/sample.go"),
										Line:  aws.Int(25),
										Label: aws.String("main"),
									},
									{
										Path:  aws.String("runtime/proc.go"),
										Line:  aws.Int(203),
										Label: aws.String("main"),
									},
									{
										Path:  aws.String("runtime/asm_amd64.s"),
										Line:  aws.Int(1373),
										Label: aws.String("goexit"),
									},
								},
							},
						},
					},
				},
				Namespace: aws.String("aws"),
				HTTP: &HTTPData{
					// Request: nil
					Response: &ResponseData{
						Status:        aws.Int(400),
						ContentLength: aws.Int(145),
					},
				},
				AWS: map[string]interface{}{
					"operation":  "DescribeTable",
					"region":     "us-west-2",
					"request_id": "END70G12L90RIJGETVF97FBV63VV4KQNSO5AEMVJF66Q9ASUAAJG",
					"retries":    0.0,
					"table_name": "does_not_exist",
				},
				Subsegments: []Segment{
					{
						Name:      aws.String("marshal"),
						ID:        aws.String("5307016134c0e0f6"),
						StartTime: aws.Float64(1595437651.685977),
						// TraceID: nil
						EndTime: aws.Float64(1595437651.6864),
					},
					{
						Name:      aws.String("attempt"),
						ID:        aws.String("54b05295d4b0460d"),
						StartTime: aws.Float64(1595437651.686414),
						// TraceID: nil
						EndTime: aws.Float64(1595437652.1967459),
						Fault:   aws.Bool(true),
						Cause: &CauseData{
							Type: CauseTypeObject,
							// ExceptionID: nil
							causeObject: causeObject{
								WorkingDirectory: aws.String("/Users/yenlinc/workplace/yenlinc/opentelemetry-collector-contrib/receiver/awsxrayreceiver/testdata/rawsegment/sampleapp"),
								// Paths: nil
								Exceptions: []Exception{
									{
										ID:      aws.String("0d836b2133ae826c"),
										Message: aws.String("ResourceNotFoundException: Requested resource not found: Table: does_not_exist not found"),
										Type:    aws.String("dynamodb.ResourceNotFoundException"),
										Remote:  aws.Bool(true),
										// Truncated: nil
										// Skipped: nil
										// Cause: nil
										Stack: []StackFrame{
											{
												Path:  aws.String("github.com/aws/aws-xray-sdk-go@v1.1.0/xray/aws.go"),
												Line:  aws.Int(139),
												Label: aws.String("glob..func7"),
											},
											{
												Path:  aws.String("github.com/aws/aws-sdk-go@v1.33.9/aws/request/handlers.go"),
												Line:  aws.Int(267),
												Label: aws.String("(*HandlerList).Run"),
											},
											{
												Path:  aws.String("github.com/aws/aws-sdk-go@v1.33.9/aws/request/request.go"),
												Line:  aws.Int(534),
												Label: aws.String("(*Request).Send"),
											},
											{
												Path:  aws.String("github.com/aws/aws-sdk-go@v1.33.9/service/dynamodb/api.go"),
												Line:  aws.Int(2275),
												Label: aws.String("(*DynamoDB).DescribeTableWithContext"),
											},
											{
												Path:  aws.String("sampleapp/sample.go"),
												Line:  aws.Int(31),
												Label: aws.String("ddbExpectedFailure.func1"),
											},
											{
												Path:  aws.String("github.com/aws/aws-xray-sdk-go@v1.1.0/xray/capture.go"),
												Line:  aws.Int(45),
												Label: aws.String("Capture"),
											},
											{
												Path:  aws.String("sampleapp/sample.go"),
												Line:  aws.Int(30),
												Label: aws.String("ddbExpectedFailure"),
											},
											{
												Path:  aws.String("sampleapp/sample.go"),
												Line:  aws.Int(25),
												Label: aws.String("main"),
											},
											{
												Path:  aws.String("runtime/proc.go"),
												Line:  aws.Int(203),
												Label: aws.String("main"),
											},
											{
												Path:  aws.String("runtime/asm_amd64.s"),
												Line:  aws.Int(1373),
												Label: aws.String("goexit"),
											},
										},
									},
								},
							},
						},
						Subsegments: []Segment{
							{
								Name:      aws.String("connect"),
								ID:        aws.String("b0a7749d2ba2936b"),
								StartTime: aws.Float64(1595437651.6869912),
								// TraceID: nil
								EndTime: aws.Float64(1595437652.1090848),
								Metadata: map[string]map[string]interface{}{
									"http": map[string]interface{}{
										"connection": map[string]interface{}{
											"reused":   false,
											"was_idle": false,
										},
									},
								},
								Subsegments: []Segment{
									{
										Name:      aws.String("dns"),
										ID:        aws.String("56604619618fb7a0"),
										StartTime: aws.Float64(1595437651.688052),
										// TraceID: nil
										EndTime: aws.Float64(1595437651.73546),
										Metadata: map[string]map[string]interface{}{
											"http": map[string]interface{}{
												"dns": map[string]interface{}{
													"addresses": []interface{}{
														map[string]interface{}{
															"IP":   "52.94.29.60",
															"Zone": "",
														},
													},
													"coalesced": false,
												},
											},
										},
									},
									{
										Name:      aws.String("dial"),
										ID:        aws.String("32ad1e63ed192121"),
										StartTime: aws.Float64(1595437651.735483),
										// TraceID: nil
										EndTime: aws.Float64(1595437651.795638),
										Metadata: map[string]map[string]interface{}{
											"http": map[string]interface{}{
												"connect": map[string]interface{}{
													"network": "tcp",
												},
											},
										},
									},
									{
										Name:      aws.String("tls"),
										ID:        aws.String("e7f66f0cac6898da"),
										StartTime: aws.Float64(1595437651.7975092),
										// TraceID: nil
										EndTime: aws.Float64(1595437652.1090329),
										Metadata: map[string]map[string]interface{}{
											"http": map[string]interface{}{
												"tls": map[string]interface{}{
													"cipher_suite":                  49199.0,
													"did_resume":                    false,
													"negotiated_protocol":           "http/1.1",
													"negotiated_protocol_is_mutual": true,
												},
											},
										},
									},
								},
							},
							{
								Name:      aws.String("request"),
								ID:        aws.String("557398c25231fe20"),
								StartTime: aws.Float64(1595437652.1091032),
								// TraceID: nil
								EndTime: aws.Float64(1595437652.1093729),
							},
							{
								Name:      aws.String("response"),
								ID:        aws.String("259dfdf07a42fb84"),
								StartTime: aws.Float64(1595437652.109379),
								// TraceID: nil
								EndTime: aws.Float64(1595437652.1958442),
							},
						},
					},
					{
						Name:      aws.String("wait"),
						ID:        aws.String("7b9f8e1c4e6b9307"),
						StartTime: aws.Float64(1595437652.197242),
						// TraceID: nil
						EndTime: aws.Float64(1595437652.1972501),
						Fault:   aws.Bool(true),
						Cause: &CauseData{
							Type: CauseTypeObject,
							// ExceptionID: nil
							causeObject: causeObject{
								WorkingDirectory: aws.String("/Users/yenlinc/workplace/yenlinc/opentelemetry-collector-contrib/receiver/awsxrayreceiver/testdata/rawsegment/sampleapp"),
								// Paths: nil
								Exceptions: []Exception{
									{
										ID:      aws.String("c69a61b725cb8d57"),
										Message: aws.String("ResourceNotFoundException: Requested resource not found: Table: does_not_exist not found"),
										Type:    aws.String("dynamodb.ResourceNotFoundException"),
										Remote:  aws.Bool(true),
										Stack: []StackFrame{
											{
												Path:  aws.String("github.com/aws/aws-xray-sdk-go@v1.1.0/xray/aws.go"),
												Line:  aws.Int(149),
												Label: aws.String("glob..func8"),
											},
											{
												Path:  aws.String("github.com/aws/aws-sdk-go@v1.33.9/aws/request/handlers.go"),
												Line:  aws.Int(267),
												Label: aws.String("(*HandlerList).Run"),
											},
											{
												Path:  aws.String("github.com/aws/aws-sdk-go@v1.33.9/aws/request/request.go"),
												Line:  aws.Int(535),
												Label: aws.String("(*Request).Send"),
											},
											{
												Path:  aws.String("github.com/aws/aws-sdk-go@v1.33.9/service/dynamodb/api.go"),
												Line:  aws.Int(2275),
												Label: aws.String("(*DynamoDB).DescribeTableWithContext"),
											},
											{
												Path:  aws.String("sampleapp/sample.go"),
												Line:  aws.Int(31),
												Label: aws.String("ddbExpectedFailure.func1"),
											},
											{
												Path:  aws.String("github.com/aws/aws-xray-sdk-go@v1.1.0/xray/capture.go"),
												Line:  aws.Int(45),
												Label: aws.String("Capture"),
											},
											{
												Path:  aws.String("sampleapp/sample.go"),
												Line:  aws.Int(30),
												Label: aws.String("ddbExpectedFailure"),
											},
											{
												Path:  aws.String("sampleapp/sample.go"),
												Line:  aws.Int(25),
												Label: aws.String("main"),
											},
											{
												Path:  aws.String("runtime/proc.go"),
												Line:  aws.Int(203),
												Label: aws.String("main"),
											},
											{
												Path:  aws.String("runtime/asm_amd64.s"),
												Line:  aws.Int(1373),
												Label: aws.String("goexit"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		AWS: map[string]interface{}{
			"xray": map[string]interface{}{
				"sdk_version": "1.1.0",
				"sdk":         "X-Ray for Go",
			},
		},
		Service: &ServiceData{
			// Version: nil
			CompilerVersion: aws.String("go1.14.3"),
			Compiler:        aws.String("gc"),
		},
	},
		actualSeg, "unmarshalled segment is different from the expected")
}

func TestTraceBodyInProgressUnmarshalled(t *testing.T) {
	content, err := ioutil.ReadFile(path.Join("../../", "testdata", "rawsegment", "minInProgress.txt"))
	assert.NoError(t, err, "can not read raw segment")

	splitBuf := make([][]byte, 2)
	separator := []byte(util.ProtocolSeparator)
	slices := util.SplitHeaderBody(zap.NewNop(), &content, &separator, &splitBuf)
	assert.True(t, len(slices[1]) > 0, "body length is 0")

	var actualSeg Segment
	err = json.Unmarshal(slices[1], &actualSeg)
	assert.NoError(t, err, "can not unmarshall body")

	assert.Equal(t, Segment{
		Name:       aws.String("LongOperation"),
		ID:         aws.String("5cc4a447f5d4d696"),
		StartTime:  aws.Float64(1595437651.680097),
		TraceID:    aws.String("1-5f187253-6a106696d56b1f4ef9eba2ed"),
		InProgress: aws.Bool(true),
	}, actualSeg, "unmarshalled segment is different from the expected")
}

func TestTraceBodyOtherTopLevelFieldsUnmarshalled(t *testing.T) {
	// Specifically, we are testing the `error`, `throttle`, `resource_arn`
	// `origin`, `parent_id`, `type`
	content, err := ioutil.ReadFile(path.Join("../../", "testdata", "rawsegment", "minOtherFields.txt"))
	assert.NoError(t, err, "can not read raw segment")

	splitBuf := make([][]byte, 2)
	separator := []byte(util.ProtocolSeparator)
	slices := util.SplitHeaderBody(zap.NewNop(), &content, &separator, &splitBuf)
	assert.True(t, len(slices[1]) > 0, "body length is 0")

	var actualSeg Segment
	err = json.Unmarshal(slices[1], &actualSeg)
	assert.NoError(t, err, "can not unmarshall body")

	assert.Equal(t, Segment{
		Name:        aws.String("OtherTopLevelFields"),
		ID:          aws.String("5cc4a447f5d4d696"),
		StartTime:   aws.Float64(1595437651.680097),
		EndTime:     aws.Float64(1595437652.197392),
		TraceID:     aws.String("1-5f187253-6a106696d56b1f4ef9eba2ed"),
		Error:       aws.Bool(false),
		Throttle:    aws.Bool(true),
		ResourceARN: aws.String("chicken"),
		Origin:      aws.String("AWS::EC2::Instance"),
		ParentID:    aws.String("defdfd9912dc5a56"),
		Type:        aws.String("subsegment"),
	}, actualSeg, "unmarshalled segment is different from the expected")
}

func TestTraceBodyCauseIsExceptionIdUnmarshalled(t *testing.T) {
	content, err := ioutil.ReadFile(path.Join("../../", "testdata", "rawsegment", "minCauseIsExceptionId.txt"))
	assert.NoError(t, err, "can not read raw segment")

	splitBuf := make([][]byte, 2)
	separator := []byte(util.ProtocolSeparator)
	slices := util.SplitHeaderBody(zap.NewNop(), &content, &separator, &splitBuf)
	assert.True(t, len(slices[1]) > 0, "body length is 0")

	var actualSeg Segment
	err = json.Unmarshal(slices[1], &actualSeg)
	assert.NoError(t, err, "can not unmarshall body")

	assert.Equal(t, Segment{
		Name:      aws.String("CauseIsExceptionID"),
		ID:        aws.String("5cc4a447f5d4d696"),
		StartTime: aws.Float64(1595437651.680097),
		EndTime:   aws.Float64(1595437652.197392),
		TraceID:   aws.String("1-5f187253-6a106696d56b1f4ef9eba2ed"),
		Fault:     aws.Bool(true),
		Cause: &CauseData{
			Type:        CauseTypeExceptionID,
			ExceptionID: aws.String("abcdefghijklmnop"),
		},
	}, actualSeg, "unmarshalled segment is different from the expected")
}

func TestTraceBodyInvalidCauseUnmarshalled(t *testing.T) {
	content, err := ioutil.ReadFile(path.Join("../../", "testdata", "rawsegment", "minCauseIsInvalid.txt"))
	assert.NoError(t, err, "can not read raw segment")

	splitBuf := make([][]byte, 2)
	separator := []byte(util.ProtocolSeparator)
	slices := util.SplitHeaderBody(zap.NewNop(), &content, &separator, &splitBuf)
	assert.True(t, len(slices[1]) > 0, "body length is 0")

	var actualSeg Segment
	err = json.Unmarshal(slices[1], &actualSeg)
	assert.EqualError(t, err,
		fmt.Sprintf(
			"the value assigned to the `cause` field does not appear to be a string: %v",
			[]byte{'2', '0', '0'},
		),
		"invalid `cause` implies invalid segment, so unmarshalling should've failed")
}
