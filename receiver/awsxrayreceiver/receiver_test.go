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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenterror"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configmodels"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/obsreport/obsreporttest"
	"go.opentelemetry.io/collector/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/udppoller"
)

func TestConsumerCantBeNil(t *testing.T) {
	addr, err := net.ResolveUDPAddr(udppoller.Transport, "localhost:0")
	assert.NoError(t, err, "should resolve UDP address")

	sock, err := net.ListenUDP(udppoller.Transport, addr)
	assert.NoError(t, err, "should be able to listen")
	defer sock.Close()
	address := sock.LocalAddr().String()

	_, err = newReceiver(
		&Config{
			NetAddr: confignet.NetAddr{
				Endpoint:  address,
				Transport: udppoller.Transport,
			},
		},
		nil,
		zap.NewNop(),
	)
	assert.True(t, errors.Is(err, componenterror.ErrNilNextConsumer), "consumer is nil should be detected")
}

func TestPollerCreationFailed(t *testing.T) {
	_, err := newReceiver(
		&Config{
			NetAddr: confignet.NetAddr{
				Endpoint:  "dontCare",
				Transport: "tcp",
			},
		},
		new(exportertest.SinkTraceExporter),
		zap.NewNop(),
	)
	assert.EqualError(t, err,
		"X-Ray receiver only supports ingesting spans through UDP, provided: tcp",
		"receiver should not be created")
}

func TestCantStartAnInstanceTwice(t *testing.T) {
	addr, err := findAvailableAddress()
	assert.NoError(t, err, "there should be address available")

	sink := new(exportertest.SinkTraceExporter)
	rcvr, err := newReceiver(
		&Config{
			NetAddr: confignet.NetAddr{
				Endpoint:  addr,
				Transport: udppoller.Transport,
			},
		},
		sink,
		zap.NewNop(),
	)
	assert.NoError(t, err, "receiver should be created")

	// start pollers
	err = rcvr.Start(context.Background(), componenttest.NewNopHost())
	assert.NoError(t, err, "should be able to start the receiver")
	defer rcvr.Shutdown(context.Background())

	err = rcvr.Start(context.Background(), componenttest.NewNopHost())
	assert.True(t, errors.Is(err, componenterror.ErrAlreadyStarted), "should not start receiver instance twice")
}

func TestCantStopAnInstanceTwice(t *testing.T) {
	addr, err := findAvailableAddress()
	assert.NoError(t, err, "there should be address available")

	sink := new(exportertest.SinkTraceExporter)
	rcvr, err := newReceiver(
		&Config{
			NetAddr: confignet.NetAddr{
				Endpoint:  addr,
				Transport: udppoller.Transport,
			},
		},
		sink,
		zap.NewNop(),
	)
	assert.NoError(t, err, "receiver should be created")

	// start pollers
	err = rcvr.Start(context.Background(), componenttest.NewNopHost())
	assert.NoError(t, err, "should be able to start receiver")

	pollerStops := make(chan bool)
	go func() {
		err = rcvr.Shutdown(context.Background())
		assert.NoError(t, err, "should be able to shutdown the receiver")
		close(pollerStops)
	}()

	testutil.WaitFor(t, func() bool {
		select {
		case _, open := <-pollerStops:
			return !open
		default:
			return false
		}
	}, "poller is not stopped")

	err = rcvr.Shutdown(context.Background())
	assert.True(t, errors.Is(err, componenterror.ErrAlreadyStopped), "should not stop receiver instance twice")
}

// TODO: Update this test to assert on the format of traces
// once the transformation from X-Ray segments -> OTLP is done.
func TestSegmentsPassedToConsumer(t *testing.T) {
	doneFn, err := obsreporttest.SetupRecordedMetricsTest()
	assert.NoError(t, err, "SetupRecordedMetricsTest should succeed")
	defer doneFn()
	const receiverName = "TestSegmentsPassedToConsumer"

	addr, rcvr, _ := createAndOptionallyStartReceiver(t, receiverName, nil, true)
	defer rcvr.Shutdown(context.Background())

	content, err := ioutil.ReadFile(path.Join(".", "testdata", "rawsegment", "ddbSample.txt"))
	assert.NoError(t, err, "can not read raw segment")

	err = writePacket(t, addr, string(content))
	assert.NoError(t, err, "can not write packet in the happy case")

	sink := rcvr.(*xrayReceiver).consumer.(*exportertest.SinkTraceExporter)

	testutil.WaitFor(t, func() bool {
		got := sink.AllTraces()
		return len(got) == 1
	}, "consumer should eventually get the X-Ray span")

	obsreporttest.CheckReceiverTracesViews(t, receiverName, udppoller.Transport, 1, 0)
}

func TestTranslatorErrorsOut(t *testing.T) {
	doneFn, err := obsreporttest.SetupRecordedMetricsTest()
	assert.NoError(t, err, "SetupRecordedMetricsTest should succeed")
	defer doneFn()

	const receiverName = "TestTranslatorErrorsOut"

	addr, rcvr, recordedLogs := createAndOptionallyStartReceiver(t, receiverName, nil, true)
	defer rcvr.Shutdown(context.Background())

	err = writePacket(t, addr, `{"format": "json", "version": 1}`+"\ninvalidSegment")
	assert.NoError(t, err, "can not write packet in the "+receiverName+" case")

	testutil.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		return len(logs) > 0 && strings.Contains(logs[len(logs)-1].Message,
			"X-Ray segment to OT span transformation failed")
	}, "poller should log warning because consumer errored out")

	obsreporttest.CheckReceiverTracesViews(t, receiverName, udppoller.Transport, 0, 1)
}

func TestSegmentsConsumerErrorsOut(t *testing.T) {
	doneFn, err := obsreporttest.SetupRecordedMetricsTest()
	assert.NoError(t, err, "SetupRecordedMetricsTest should succeed")
	defer doneFn()

	const receiverName = "TestSegmentsConsumerErrorsOut"

	addr, rcvr, recordedLogs := createAndOptionallyStartReceiver(t, receiverName,
		&mockConsumer{consumeErr: errors.New("can't consume traces")},
		true)
	defer rcvr.Shutdown(context.Background())

	content, err := ioutil.ReadFile(path.Join(".", "testdata", "rawsegment", "serverSample.txt"))
	assert.NoError(t, err, "can not read raw segment")

	err = writePacket(t, addr, string(content))
	assert.NoError(t, err, "can not write packet")

	testutil.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		return len(logs) > 0 && strings.Contains(logs[len(logs)-1].Message,
			"Trace consumer errored out")
	}, "poller should log warning because consumer errored out")

	obsreporttest.CheckReceiverTracesViews(t, receiverName, udppoller.Transport, 0, 1)
}

type mockConsumer struct {
	mu         sync.Mutex
	consumeErr error
	traces     pdata.Traces
}

func (m *mockConsumer) ConsumeTraces(ctx context.Context, td pdata.Traces) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumeErr != nil {
		return m.consumeErr
	}
	m.traces = td
	return nil
}

func createAndOptionallyStartReceiver(
	t *testing.T,
	receiverName string,
	csu consumer.TraceConsumer,
	start bool) (string, component.TraceReceiver, *observer.ObservedLogs) {
	addr, err := findAvailableAddress()
	assert.NoError(t, err, "there should be address available")

	var sink consumer.TraceConsumer
	if csu == nil {
		sink = new(exportertest.SinkTraceExporter)
	} else {
		sink = csu
	}

	logger, recorded := logSetup()
	rcvr, err := newReceiver(
		&Config{
			ReceiverSettings: configmodels.ReceiverSettings{
				NameVal: receiverName,
			},
			NetAddr: confignet.NetAddr{
				Endpoint:  addr,
				Transport: udppoller.Transport,
			},
		},
		sink,
		logger,
	)
	assert.NoError(t, err, "receiver should be created")

	if start {
		err = rcvr.Start(context.Background(), componenttest.NewNopHost())
		assert.NoError(t, err, "receiver should be started")
	}
	return addr, rcvr, recorded
}

// findAvailableAddress finds an available local address+port and returns it.
// There might be race condition on the address returned by this function if
// there's some other code that grab the address before we can listen on it.
func findAvailableAddress() (string, error) {
	addr, err := net.ResolveUDPAddr(udppoller.Transport, "localhost:0")
	if err != nil {
		return "", err
	}

	sock, err := net.ListenUDP(udppoller.Transport, addr)
	if err != nil {
		return "", err
	}
	defer sock.Close()
	return sock.LocalAddr().String(), nil
}

func writePacket(t *testing.T, addr, toWrite string) error {
	conn, err := net.Dial(udppoller.Transport, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	n, err := fmt.Fprint(conn, toWrite)
	if err != nil {
		return err
	}
	assert.Equal(t, len(toWrite), n, "exunpected number of bytes written")
	return nil
}

func logSetup() (*zap.Logger, *observer.ObservedLogs) {
	core, recorded := observer.New(zapcore.InfoLevel)
	return zap.New(core), recorded
}
