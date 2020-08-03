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
)

const (
	xrayInProgressAttribute = "aws.xray.inprogress"
)

func addBoolToSpan(val *bool, attrKey string, span *pdata.Span) {
	if val != nil {
		attrs := span.Attributes()
		attrs.UpsertBool(attrKey, *val)
	}
}

func addStringToSpan(val *string, attrKey string, span *pdata.Span) {
	if val != nil {
		attrs.span.Attributes()
		attrs.UpsertString(attrKey, *val)
	}
}
