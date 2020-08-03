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
	"strconv"

	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/translator/conventions"

	expTrans "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/awsxrayexporter/translator"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/tracesegment"
)

// https://docs.aws.amazon.com/xray/latest/devguide/xray-api-segmentdocuments.html#api-segmentdocuments-aws
func addAWSToResource(aws *tracesegment.AWSData, rs *pdata.Resource) {
	attrs := rs.Attributes()
	if aws == nil {
		// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/aws.go#L153
		attrs.UpsertString(conventions.AttributeCloudProvider, "nonAWS")
		return
	}

	attrs.UpsertString(conventions.AttributeCloudProvider, "aws")
	if aws.AccountID != nil {
		attrs.UpsertString(conventions.AttributeCloudAccount, *aws.AccountID)
	}
	if ec2 := aws.EC2; ec2 != nil {
		attrs.UpsertString(conventions.AttributeCloudZone, *ec2.AvailabilityZone)
		attrs.UpsertString(conventions.AttributeHostID, *ec2.InstanceID)
		attrs.UpsertString(conventions.AttributeHostType, *ec2.InstanceSize)
		attrs.UpsertString(conventions.AttributeHostImageID, *ec2.AmiID)
	} else if ecs := aws.ECS; ecs != nil {
		attrs.UpsertString(conventions.AttributeContainerName, *ecs.ContainerName)
	} else if bs := aws.Beanstalk; bs != nil {
		attrs.UpsertString(conventions.AttributeServiceNamespace, *bs.Environment)
		attrs.UpsertString(conventions.AttributeServiceInstance, strconv.FormatInt(*bs.DeploymentID, 10))
		attrs.UpsertString(conventions.AttributeServiceVersion, *bs.VersionLabel)
	}
}

func addAWSToSpan(aws *tracesegment.AWSData, span *pdata.Span) {
	if aws != nil {
		attrs := span.Attributes()

		if aws.Operation != nil {
			attrs.UpsertString(expTrans.AWSOperationAttribute, *aws.Operation)
		}

		if aws.RemoteRegion != nil {
			attrs.UpsertString(expTrans.AWSRegionAttribute, *aws.RemoteRegion)
		}

		if aws.RequestID != nil {
			attrs.UpsertString(expTrans.AWSRequestIDAttribute, *aws.RequestID)
		}

		if aws.QueueURL != nil {
			attrs.UpsertString(expTrans.AWSQueueURLAttribute, *aws.QueueURL)
		}

		if aws.TableName != nil {
			attrs.UpsertString(expTrans.AWSTableNameAttribute, *aws.TableName)
		}
	}
}
