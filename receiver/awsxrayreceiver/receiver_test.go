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
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configmodels"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/testutils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestUDPPortUnavailable(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	assert.NoError(t, err, "should resolve UDP address")

	sock, err := net.ListenUDP("udp", addr)
	assert.NoError(t, err, "should be able to listen")
	defer sock.Close()
	address := sock.LocalAddr().String()

	sink := new(exportertest.SinkTraceExporter)
	_, err = newReceiver(
		&Config{
			ReceiverSettings: configmodels.ReceiverSettings{
				Endpoint: address,
			},
		},
		sink,
		zap.NewNop(),
	)
	assert.Error(t, err, "should have failed to create a new receiver")
	assert.Contains(t, err.Error(), "address already in use", "error message should complain about address in-use")
}

func TestShutdownStopsPollers(t *testing.T) {
	addr, err := findAvailableAddress()
	assert.NoError(t, err, "there should be address available")

	sink := new(exportertest.SinkTraceExporter)
	rcvr, err := newReceiver(
		&Config{
			ReceiverSettings: configmodels.ReceiverSettings{
				Endpoint: addr,
			},
		},
		sink,
		zap.NewNop(),
	)
	assert.NoError(t, err, "receiver should be created")

	// start pollers
	rcvr.Start(context.Background(), componenttest.NewNopHost())
	pollerStops := make(chan bool)
	go func() {
		err = rcvr.Shutdown(context.Background())
		assert.NoError(t, err, "should be able to shutdown the receiver")
		close(pollerStops)
	}()

	testutils.WaitFor(t, func() bool {
		select {
		case _, open := <-pollerStops:
			return !open
		default:
			return false
		}
	}, "poller is not stopped")
}

func TestSegmentsPassedToConsumer(t *testing.T) {
	addr, rcvr, _ := createAndOptionallyStartReceiver(t, true)
	defer rcvr.Shutdown(context.Background())

	// valid header with invalid body (for now this is ok because we haven't
	// implemented the X-Ray segment -> OT format conversion)
	err := writePacket(t, addr, `{"format": "json", "version": 1}`+"\nBody")
	assert.NoError(t, err, "can not write packet in the happy case")

	sink := rcvr.(*xrayReceiver).consumer.(*exportertest.SinkTraceExporter)

	testutils.WaitFor(t, func() bool {
		got := sink.AllTraces()
		if len(got) == 1 {
			return true
		}
		return false
	}, "consumer should eventually get the X-Ray span")
}

func TestIssuesOccurredWhenSplitHeaderBody(t *testing.T) {
	addr, rcvr, recordedLogs := createAndOptionallyStartReceiver(t, true)
	defer rcvr.Shutdown(context.Background())

	err := writePacket(t, addr, "Header\n") // no body
	assert.NoError(t, err, "can not write packet in the no body test case")
	testutils.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		fmt.Println(logs)
		if len(logs) > 0 && strings.Contains(logs[len(logs)-1].Message, "Missing header or segment") {
			return true
		}
		return false
	}, "poller should reject segment")
}

func TestInvalidHeader(t *testing.T) {
	addr, rcvr, recordedLogs := createAndOptionallyStartReceiver(t, true)
	defer rcvr.Shutdown(context.Background())

	randString, _ := uuid.NewRandom()
	// the header (i.e. the portion before \n) is invalid
	err := writePacket(t, addr, randString.String()+"\nBody")
	assert.NoError(t, err, "can not write packet in the invalid header test case")
	testutils.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		lastEntry := logs[len(logs)-1]
		if len(logs) > 0 &&
			strings.Contains(lastEntry.Message, "Invalid header") &&
			// assert the invalid header is equal to the random string we passed
			// in previously as the invalid header.
			strings.Compare(string(lastEntry.Context[0].Interface.([]byte)), randString.String()) == 0 {
			return true
		}
		return false
	}, "poller should reject segment")
}

func TestSocketReadTemporaryNetError(t *testing.T) {
	_, rcvr, recordedLogs := createAndOptionallyStartReceiver(t, false)
	// close the actual socket because we are going to mock it out below
	rcvr.(*xrayReceiver).udpSock.Close()

	randErrStr, _ := uuid.NewRandom()
	rcvr.(*xrayReceiver).udpSock = &mockSocketConn{
		expectedOutput: []byte("dontCare"),
		expectedError: &mockTempNetError{
			mockErrStr: randErrStr.String(),
		},
	}

	err := rcvr.Start(context.Background(), componenttest.NewNopHost())
	assert.NoError(t, err, "receiver with mock socket should be started")

	testutils.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		lastEntry := logs[len(logs)-1]
		if len(logs) > 0 &&
			strings.Contains(lastEntry.Message, "X-Ray receiver read net error") &&
			lastEntry.Context[0].Type == zapcore.ErrorType &&
			strings.Compare(lastEntry.Context[0].Interface.(error).Error(), randErrStr.String()) == 0 {
			return true
		}
		return false
	}, "poller should encounter net read error")
}

func TestSocketGenericReadError(t *testing.T) {
	_, rcvr, recordedLogs := createAndOptionallyStartReceiver(t, false)
	// close the actual socket because we are going to mock it out below
	rcvr.(*xrayReceiver).udpSock.Close()

	randErrStr, _ := uuid.NewRandom()
	rcvr.(*xrayReceiver).udpSock = &mockSocketConn{
		expectedOutput: []byte("dontCare"),
		expectedError: &mockGenericErr{
			mockErrStr: randErrStr.String(),
		},
	}

	err := rcvr.Start(context.Background(), componenttest.NewNopHost())
	assert.NoError(t, err, "receiver with mock socket should be started")

	testutils.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		lastEntry := logs[len(logs)-1]
		if len(logs) > 0 &&
			strings.Contains(lastEntry.Message, "X-Ray receiver socket read error") &&
			lastEntry.Context[0].Type == zapcore.ErrorType &&
			strings.Compare(lastEntry.Context[0].Interface.(error).Error(), randErrStr.String()) == 0 {
			return true
		}
		return false
	}, "poller should encounter generic socket read error")
}

type mockTempNetError struct {
	mockErrStr string
}

func (m *mockTempNetError) Error() string {
	return m.mockErrStr
}

func (m *mockTempNetError) Timeout() bool {
	return false
}

func (m *mockTempNetError) Temporary() bool {
	return true
}

type mockGenericErr struct {
	mockErrStr string
}

func (m *mockGenericErr) Error() string {
	return m.mockErrStr
}

type mockSocketConn struct {
	expectedOutput []byte
	expectedError  error
}

func (m *mockSocketConn) Read(b []byte) (int, error) {
	copied := copy(b, m.expectedOutput)
	return copied, m.expectedError
}

func (m *mockSocketConn) Close() {}

func createAndOptionallyStartReceiver(t *testing.T, start bool) (string, component.TraceReceiver, *observer.ObservedLogs) {
	addr, err := findAvailableAddress()
	assert.NoError(t, err, "there should be address available")

	sink := new(exportertest.SinkTraceExporter)
	logger, recorded := logSetup()
	rcvr, err := newReceiver(
		&Config{
			ReceiverSettings: configmodels.ReceiverSettings{
				Endpoint: addr,
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
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		return "", err
	}

	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		return "", err
	}
	defer sock.Close()
	return sock.LocalAddr().String(), nil
}

func writePacket(t *testing.T, addr, toWrite string) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	n, err := fmt.Fprintf(conn, toWrite)
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
