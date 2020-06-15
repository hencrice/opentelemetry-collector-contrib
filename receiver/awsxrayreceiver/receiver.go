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

package awsxrayreceiver

import (
	"context"

	"go.opentelemetry.io/collector/component"
)

// ensure the xrayReceiver implements the TraceReceiver interface
var _ component.TraceReceiver = (*xrayReceiver)(nil)

// xrayReceiver implements the component.TraceReceiver interface for converting
// AWS X-Ray segment document into the OT internal trace format.
type xrayReceiver struct {
}

func (x *xrayReceiver) Start(ctx context.Context, host component.Host) error {
	return nil
}

func (x *xrayReceiver) Shutdown(ctx context.Context) error {
	return nil
}
