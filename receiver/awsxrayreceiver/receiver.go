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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/obsreport"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/pkg/socketconn"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/pkg/socketconn/udp"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/pkg/tracesegment"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/pkg/util"
)

const (
	protocolSeparator = "\n"
	// number of goroutines polling the UDP socket.
	// https://github.com/aws/aws-xray-daemon/blob/master/pkg/cfg/cfg.go#L184
	maxPollerCount = 2

	// size of the buffer used by each poller.
	// https://github.com/aws/aws-xray-daemon/blob/master/pkg/cfg/cfg.go#L182
	// https://github.com/aws/aws-xray-daemon/blob/master/cmd/tracing/daemon.go#L171
	pollerBufferSizeKB = 64 * 1024

	transport = "udp"
)

// ensure the xrayReceiver implements the TraceReceiver interface
var _ component.TraceReceiver = (*xrayReceiver)(nil)

// xrayReceiver implements the component.TraceReceiver interface for converting
// AWS X-Ray segment document into the OT internal trace format.
type xrayReceiver struct {
	instanceName string
	udpSock      socketconn.SocketConn
	logger       *zap.Logger
	consumer     consumer.TraceConsumer
	wg           sync.WaitGroup
	longLivedCtx context.Context
}

func newReceiver(config *Config,
	consumer consumer.TraceConsumer,
	logger *zap.Logger) (component.TraceReceiver, error) {

	logger.Info("listening on endpoint for X-Ray segments",
		zap.String(transport, config.ReceiverSettings.Endpoint))
	sock, err := udp.New(config.ReceiverSettings.Endpoint)
	if err != nil {
		return nil, err
	}

	return &xrayReceiver{
		instanceName: config.Name(),
		udpSock:      sock,
		logger:       logger,
		consumer:     consumer,
	}, nil
}

func (x *xrayReceiver) Start(ctx context.Context, host component.Host) error {
	// TODO: Might want to pass `host` into read() below to report a fatal error
	x.longLivedCtx = obsreport.ReceiverContext(ctx, x.instanceName, transport, "")
	for i := 0; i < maxPollerCount; i++ {
		x.wg.Add(1)
		go x.poll()
	}
	return nil
}

func (x *xrayReceiver) Shutdown(_ context.Context) error {
	x.udpSock.Close()
	x.wg.Wait()
	return nil
}

// Reference for this port:
// https://github.com/aws/aws-xray-daemon/blob/master/cmd/tracing/daemon.go#L257
func (x *xrayReceiver) read(buf *[]byte) (int, error) {
	bufVal := *buf
	rlen, err := x.udpSock.Read(bufVal)
	if err == nil {
		return rlen, nil
	} else {
		switch err := err.(type) {
		case net.Error:
			if !err.Temporary() {
				return -1, fmt.Errorf("read from UDP socket: %w", &errIrrecoverable{err})
			}
		default:
			return 0, fmt.Errorf("read from UDP socket: %w", &errRecoverable{err})
		}
		return 0, fmt.Errorf("read from UDP socket: %w", &errRecoverable{err})
	}
}

// this function references the implementation in:
// https://github.com/aws/aws-xray-daemon/blob/master/cmd/tracing/daemon.go#L275
// However, it intentionally avoids using a buffer pool and just stick to
// a local buffer for simplicity and improve concurrency (because in the orignal
// implementation, the buffer pool is shared between 2 poll() cals executed by
// 2 goroutines, which requires locking/unlocking a sync.Mutex whenever
// a buffer is Get()/Return()). Also, the buffer returns by Get()
// (i.e. https://github.com/aws/aws-xray-daemon/blob/d2331c8c4538e55c237b05306a3cf2e919a41ba9/pkg/bufferpool/bufferpool.go#L28)
// is the same size as the fallBackBuffer
// (https://github.com/aws/aws-xray-daemon/blob/master/cmd/tracing/daemon.go#L277)
func (x *xrayReceiver) poll() {
	defer x.wg.Done()
	separator := []byte(protocolSeparator)
	buffer := make([]byte, pollerBufferSizeKB)
	splitBuf := make([][]byte, 2)

	var (
		errRecv   *errRecoverable
		errIrrecv *errIrrecoverable
	)

	for {
		// https://pkg.go.dev/go.opentelemetry.io/collector@v0.4.1-0.20200622191610-a8db6271f90a/obsreport?tab=doc#EndTraceDataReceiveOp
		// at corresponding places in the for loop below.
		ctx := obsreport.StartTraceDataReceiveOp(
			x.longLivedCtx,
			x.instanceName,
			transport,
			obsreport.WithLongLivedCtx())

		bufPointer := &buffer
		rlen, err := x.read(bufPointer)
		if err != nil && errors.As(err, &errIrrecv) {
			x.logger.Error("irrecoverable socket read error. Exiting poller",
				zap.Error(err))
			obsreport.EndTraceDataReceiveOp(ctx, typeStr, 0, err)
			return
		} else if errors.As(err, &errRecv) {
			x.logger.Error("recoverable socket read error", zap.Error(err))
			obsreport.EndTraceDataReceiveOp(ctx, typeStr, 0, err)
			continue
		}

		bufMessage := buffer[0:rlen]

		slices := util.SplitHeaderBody(x.logger, &bufMessage, &separator, &splitBuf)
		if len(slices[1]) == 0 {
			x.logger.Warn("Missing header or segment", zap.ByteString("value", slices[0]))
			obsreport.EndTraceDataReceiveOp(ctx, typeStr, 0,
				errors.New("dropped span(s) due to missing header or segment"))
			continue
		}

		header := slices[0]
		// payload := slices[1]
		headerInfo := tracesegment.Header{}
		json.Unmarshal(header, &headerInfo)

		switch headerInfo.IsValid() {
		case true:
		default:
			x.logger.Warn("Invalid header", zap.ByteString("header", header))
			obsreport.EndTraceDataReceiveOp(ctx, typeStr, 0,
				errors.New("dropped span(s) due to invalid header"))
			continue
		}

		// TODO: Transform payload to consumer.ConsumeTraceData. For now
		// we are just dropping the ingested X-Ray segments.
		err = x.consumer.ConsumeTraces(ctx, pdata.NewTraces())
		if err != nil {
			// TODO: Update the count of the received spans to the actual number
			// For now this can't be done because we haven't parsed the `payload`
			// above
			obsreport.EndTraceDataReceiveOp(ctx, typeStr, 1, err)
			continue
		}
		// TODO: Update the count of the received spans to the actual number
		// For now this can't be done because we haven't parsed the `payload`
		// above
		obsreport.EndTraceDataReceiveOp(ctx, typeStr, 1, nil)
	}
}