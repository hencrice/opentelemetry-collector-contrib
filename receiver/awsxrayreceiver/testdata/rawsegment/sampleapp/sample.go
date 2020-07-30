// +build xraysegmentdump

package main

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-xray-sdk-go/xray"
)

var dynamo *dynamodb.DynamoDB

func main() {
	dynamo = dynamodb.New(session.Must(session.NewSession(
		&aws.Config{
			Region: aws.String("us-west-2")},
	)))
	xray.AWS(dynamo.Client)

	ctx, seg := xray.BeginSegment(context.Background(), "DDB.TableDoesNotExist")
	seg.User = "xraysegmentdump"
	err := ddbExpectedFailure(ctx)
	seg.Close(err)
}

func ddbExpectedFailure(ctx context.Context) error {
	return xray.Capture(ctx, "DDB.TableDoesNotExist.DescribeTable", func(ctx1 context.Context) error {
		_, err := dynamo.DescribeTableWithContext(ctx, &dynamodb.DescribeTableInput{
			TableName: aws.String("does_not_exist"),
		})
		xray.AddAnnotation(ctx, "DDB.TableDoesNotExist.DescribeTable.Annotation", "anno")
		xray.AddMetadata(ctx, "DDB.TableDoesNotExist.DescribeTable.AddMetadata", "meta")
		return err
	})
}
