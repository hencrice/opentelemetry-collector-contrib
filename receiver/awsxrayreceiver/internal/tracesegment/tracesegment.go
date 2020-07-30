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

// Copyright 2018-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package tracesegment

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// TypeStr is the type and ingest format of this receiver
	TypeStr = "aws_xray"
)

// Header stores header of trace segment.
type Header struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
}

// IsValid validates Header.
func (t Header) IsValid() bool {
	return strings.EqualFold(t.Format, "json") && t.Version == 1
}

type causeType int

const (
	// CauseTypeExceptionID indicates that the type of the `cause`
	// field is a string
	CauseTypeExceptionID causeType = iota + 1
	// CauseTypeObject indicates that the type of the `cause`
	// field is an object
	CauseTypeObject
)

// Segment schema is documented in xray-segmentdocument-schema-v1.0.0 listed
// on https://docs.aws.amazon.com/xray/latest/devguide/xray-api-segmentdocuments.html
type Segment struct {
	// Required fields
	Name      *string  `json:"name"`
	ID        *string  `json:"id"`
	StartTime *float64 `json:"start_time"`
	TraceID   *string  `json:"trace_id"`

	// Optional fields
	EndTime      *float64                          `json:"end_time"`
	InProgress   *bool                             `json:"in_progress"`
	Fault        *bool                             `json:"fault,omitempty"`
	Error        *bool                             `json:"error,omitempty"`
	Throttle     *bool                             `json:"throttle,omitempty"`
	User         *string                           `json:"user,omitempty"`
	ResourceARN  *string                           `json:"resource_arn,omitempty"`
	Origin       *string                           `json:"origin,omitempty"`
	ParentID     *string                           `json:"parent_id,omitempty"`
	Cause        *CauseData                        `json:"cause,omitempty"`
	Annotations  map[string]interface{}            `json:"annotations,omitempty"`
	Metadata     map[string]map[string]interface{} `json:"metadata,omitempty"`
	Type         *string                           `json:"type,omitempty"`
	Subsegments  []Segment                         `json:"subsegments,omitempty"`
	HTTP         *HTTPData                         `json:"http,omitempty"`
	AWS          map[string]interface{}            `json:"aws,omitempty"`
	SQL          *SQLData                          `json:"sql,omitempty"`
	Service      *ServiceData                      `json:"service,omitempty"`
	PrecursorIDs []string                          `json:"precursor_ids,omitempty"`

	Namespace *string `json:"namespace,omitempty"`
	Traced    *bool   `json:"traced,omitempty"`
}

// CauseData is the container that contains the `cause` field
type CauseData struct {
	Type causeType `json:"-"`
	// it will contain one of ExceptionID or (WorkingDirectory, Paths, Exceptions)
	ExceptionID *string `json:"-"`

	causeObject
}

type causeObject struct {
	WorkingDirectory *string     `json:"working_directory,omitempty"`
	Paths            []string    `json:"paths,omitempty"`
	Exceptions       []Exception `json:"exceptions,omitempty"`
}

// UnmarshalJSON is the custom unmarshaller for the cause field
func (c *CauseData) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &c.causeObject)
	if err == nil {
		c.Type = CauseTypeObject
		return nil
	}
	rawStr := string(data)
	if len(rawStr) > 0 && (rawStr[0] != '"' || rawStr[len(rawStr)-1] != '"') {
		return fmt.Errorf("the value assigned to the `cause` field does not appear to be a string: %v", data)
	}
	exceptionID := rawStr[1 : len(rawStr)-1]

	c.Type = CauseTypeExceptionID
	c.ExceptionID = &exceptionID
	return nil
}

// Exception represents an exception occurred
type Exception struct {
	ID        *string      `json:"id,omitempty"`
	Message   *string      `json:"message,omitempty"`
	Type      *string      `json:"type,omitempty"`
	Remote    *bool        `json:"remote,omitempty"`
	Truncated *int         `json:"truncated,omitempty"`
	Skipped   *int         `json:"skipped,omitempty"`
	Cause     *string      `json:"cause,omitempty"`
	Stack     []StackFrame `json:"stack,omitempty"`
}

// StackFrame represents a frame in the stack when an exception occurred
type StackFrame struct {
	Path  *string `json:"path,omitempty"`
	Line  *int    `json:"line,omitempty"`
	Label *string `json:"label,omitempty"`
}

// HTTPData provides the shape for unmarshalling request and response fields.
type HTTPData struct {
	Request  *RequestData  `json:"request,omitempty"`
	Response *ResponseData `json:"response,omitempty"`
}

// RequestData provides the shape for unmarshalling the request field.
type RequestData struct {
	// Available in segment
	XForwardedFor *bool `json:"x_forwarded_for,omitempty"`

	// Available in both segment and subsegments
	Method    *string `json:"method,omitempty"`
	URL       *string `json:"url,omitempty"`
	UserAgent *string `json:"user_agent,omitempty"`
	ClientIP  *string `json:"client_ip,omitempty"`
}

// ResponseData provides the shape for unmarshalling the response field.
type ResponseData struct {
	Status        *int `json:"status,omitempty"`
	ContentLength *int `json:"content_length,omitempty"`
}

// ECSData provides the shape for unmarshalling the ecs field.
type ECSData struct {
	Container *string `json:"container,omitempty"`
}

// EC2Data provides the shape for unmarshalling the ec2 field.
type EC2Data struct {
	InstanceID       *string `json:"instance_id,omitempty"`
	AvailabilityZone *string `json:"availability_zone,omitempty"`
}

// ElasticBeanstalkData provides the shape for unmarshalling the elastic_beanstalk field.
type ElasticBeanstalkData struct {
	EnvironmentName *string `json:"environment_name,omitempty"`
	VersionLabel    *string `json:"version_label,omitempty"`
	DeploymentID    *int    `json:"deployment_id,omitempty"`
}

// TracingData provides the shape for unmarshalling the tracing data.
type TracingData struct {
	SDK *string `json:"sdk,omitempty"`
}

// XRayData provides the shape for unmarshalling the xray field
type XRayData struct {
	SDKVersion *string `json:"sdk_version,omitempty"`
	SDK        *string `json:"sdk,omitempty"`
}

// SQLData provides the shape for unmarshalling the sql field.
type SQLData struct {
	ConnectionString *string `json:"connection_string,omitempty"`
	URL              *string `json:"url,omitempty"` // host:port/database
	SanitizedQuery   *string `json:"sanitized_query,omitempty"`
	DatabaseType     *string `json:"database_type,omitempty"`
	DatabaseVersion  *string `json:"database_version,omitempty"`
	DriverVersion    *string `json:"driver_version,omitempty"`
	User             *string `json:"user,omitempty"`
	Preparation      *string `json:"preparation,omitempty"` // "statement" / "call"
}

// ServiceData provides the shape for unmarshalling the service field.
type ServiceData struct {
	Version         *string `json:"version,omitempty"`
	CompilerVersion *string `json:"compiler_version,omitempty"`
	Compiler        *string `json:"compiler,omitempty"`
}