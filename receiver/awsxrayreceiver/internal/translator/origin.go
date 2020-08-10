// Copyright The OpenTelemetry Authors
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
	"go.opentelemetry.io/collector/translator/conventions"
)

// AWS X-Ray acceptable values for origin field.
const (
	originEC2 = "AWS::EC2::Instance"
	originECS = "AWS::ECS::Container"
	originEB  = "AWS::ElasticBeanstalk::Environment"
)

func addOrigin(origin *string, attrs *pdata.AttributeMap) error {
	if origin == nil {
		// resource will be nil and is treated by the AWS X-Ray exporter (in
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/segment.go#L253)
		// as origin == "AWS::EC2::Instance"
		return nil
	}

	switch *origin {
	case originEB:
		attrs.UpsertString(conventions.AttributeServiceInstance, *origin)
	case originECS:
		attrs.UpsertString(conventions.AttributeContainerName, *origin)
	case originEC2:
		// X-Ray exporter treats this case as origin == "AWS::EC2::Instance"
		return nil
	default:
		return fmt.Errorf("recognized")
	}
	return nil
}
