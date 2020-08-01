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
)

func addOrigin(origin *string, attrs *pdata.AttributeMap) {
	if origin == nil || *origin == originEC2 {
		// resource will be nil and is treated by the AWS X-Ray exporter (in
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/segment.go#L253)
		// as origin == "AWS::EC2::Instance"
		return
	}

	if *origin == originEB {
		attrs.UpsertString(conventions.AttributeServiceInstance, *origin)
	} else if *origin == originECS {
		attrs.UpsertString(conventions.AttributeContainerName, *origin)
	}
}
