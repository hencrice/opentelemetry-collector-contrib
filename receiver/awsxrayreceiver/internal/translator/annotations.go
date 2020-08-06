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

	"go.opentelemetry.io/collector/consumer/pdata"
)

func addAnnotations(annos map[string]interface{}, attrs *pdata.AttributeMap) {
	for k, v := range annos {
		switch t := v.(type) {
		case int, int32, int64:
			attrs.UpsertInt(k, t.(int64))
		case string:
			attrs.UpsertString(k, t)
		case bool:
			attrs.UpsertBool(k, t)
		case float32, float64:
			attrs.UpsertDouble(k, t.(float64))
		default:
			attrs.UpsertString(k, fmt.Sprintf("%v", t))
		}
	}
}
