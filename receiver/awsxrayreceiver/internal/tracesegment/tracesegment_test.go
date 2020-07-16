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
				ID:        aws.String("aef48bafb51c6326"),
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
										Label: aws.String("ddbExpectedFailure"),
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
			},
		},
	},
		actualSeg, "unmarshalled segment is different from the expected")
}
