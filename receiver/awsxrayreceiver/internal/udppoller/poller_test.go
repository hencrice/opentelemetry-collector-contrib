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

package udppoller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	internalErr "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/errors"
)

func TestNonUDPTransport(t *testing.T) {
	_, err := New(
		&Config{
			Transport:          "tcp",
			NumOfPollerToStart: 2,
		},
		zap.NewNop(),
	)
	assert.EqualError(t, err,
		"X-Ray receiver only supports ingesting spans through UDP, provided: tcp")
}

func TestInvalidEndpoint(t *testing.T) {
	_, err := New(
		&Config{
			Endpoint:           "invalidAddr",
			Transport:          "udp",
			NumOfPollerToStart: 2,
		},
		zap.NewNop(),
	)
	assert.EqualError(t, err, "address invalidAddr: missing port in address")
}

func TestUDPPortUnavailable(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	assert.NoError(t, err, "should resolve UDP address")

	sock, err := net.ListenUDP("udp", addr)
	assert.NoError(t, err, "should be able to listen")
	defer sock.Close()
	address := sock.LocalAddr().String()

	_, err = New(
		&Config{
			Transport:          Transport,
			Endpoint:           address,
			NumOfPollerToStart: 2,
		},
		zap.NewNop(),
	)

	assert.Error(t, err, "should have failed to create a new receiver")
	assert.Contains(t, err.Error(), "address already in use", "error message should complain about address in-use")
}

func TestCloseStopsPoller(t *testing.T) {
	addr, err := findAvailableAddress()
	assert.NoError(t, err, "there should be address available")

	p, err := New(
		&Config{
			Transport:          Transport,
			Endpoint:           addr,
			NumOfPollerToStart: 2,
		},
		zap.NewNop(),
	)
	assert.NoError(t, err, "poller should be created")

	// start pollers
	segChan := p.SegmentsChan()
	p.Start(context.Background())

	err = p.Close()
	assert.NoError(t, err, "should be able to close the poller")

	_, open := <-segChan
	assert.False(t, open, "output channel should be closed")

	err = p.(*poller).udpSock.Close()
	assert.Error(t, err, "a socket should not be closed twice")
}

func TestSuccessfullyPollPacket(t *testing.T) {
	addr, p, _ := createAndOptionallyStartPoller(t, true)
	defer p.Close()

	randString, _ := uuid.NewRandom()
	rawData := []byte(`{"format": "json", "version": 1}` + "\n" + randString.String())
	err := writePacket(t, addr, string(rawData))
	assert.NoError(t, err, "can not write packet in the no body test case")

	testutil.WaitFor(t, func() bool {
		select {
		case seg, open := <-p.(*poller).segChan:
			assert.True(t, open, "segChan should not be closed")
			assert.Equal(t, randString.String(), string(seg.Payload))
			return true
		default:
			return false
		}
		return false
	}, "poller should return parsed segment")
}

func TestIncompletePacketNoSeparator(t *testing.T) {
	addr, p, recordedLogs := createAndOptionallyStartPoller(t, true)
	defer p.Close()

	rawData := []byte(`{"format": "json", "version": 1}`) // no separator
	err := writePacket(t, addr, string(rawData))
	assert.NoError(t, err, "can not write packet in the no body test case")
	testutil.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		lastEntry := logs[len(logs)-1]
		var errRecv *internalErr.ErrRecoverable
		if strings.Contains(lastEntry.Message, "Failed to split segment header and body") &&
			errors.As(lastEntry.Context[0].Interface.(error), &errRecv) &&
			strings.Compare(
				errors.Unwrap(
					lastEntry.Context[0].Interface.(error)).Error(),
				fmt.Sprintf("unable to split incoming data as header and segment, incoming bytes: %v", rawData)) == 0 {
			return true
		}
		return false
	}, "poller should reject segment")
}

func TestIncompletePacketNoBody(t *testing.T) {
	addr, p, recordedLogs := createAndOptionallyStartPoller(t, true)
	defer p.Close()

	rawData := []byte(`{"format": "json", "version": 1}` + "\n") // no body
	err := writePacket(t, addr, string(rawData))
	assert.NoError(t, err, "can not write packet in the no body test case")
	testutil.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		lastEntry := logs[len(logs)-1]
		if strings.Contains(lastEntry.Message, "Missing body") &&
			lastEntry.Context[0].String == "json" &&
			lastEntry.Context[1].Integer == 1 {
			return true
		}
		return false
	}, "poller should log missing body")
}

func TestNonJsonHeader(t *testing.T) {
	addr, p, recordedLogs := createAndOptionallyStartPoller(t, true)
	defer p.Close()

	// the header (i.e. the portion before \n) is invalid
	err := writePacket(t, addr, "nonJson\nBody")
	assert.NoError(t, err, "can not write packet in the invalid header test case")
	testutil.WaitFor(t, func() bool {
		var errRecv *internalErr.ErrRecoverable
		logs := recordedLogs.All()
		lastEntry := logs[len(logs)-1]

		if lastEntry.Message == "Failed to split segment header and body" &&
			// assert the invalid header is equal to the random string we passed
			// in previously as the invalid header.
			errors.As(lastEntry.Context[0].Interface.(error), &errRecv) &&
			strings.Contains(lastEntry.Context[0].Interface.(error).Error(),
				"invalid character 'o'") {
			return true
		}
		return false
	}, "poller should reject segment")
}

func TestJsonInvalidHeader(t *testing.T) {
	addr, p, recordedLogs := createAndOptionallyStartPoller(t, true)
	defer p.Close()

	randString, _ := uuid.NewRandom()
	// the header (i.e. the portion before \n) is invalid
	err := writePacket(t, addr,
		fmt.Sprintf(`{"format": "%s", "version": 1}`, randString.String())+"\nBody")
	assert.NoError(t, err, "can not write packet in the invalid header test case")
	testutil.WaitFor(t, func() bool {
		var errRecv *internalErr.ErrRecoverable
		logs := recordedLogs.All()
		lastEntry := logs[len(logs)-1]
		if lastEntry.Message == "Failed to split segment header and body" &&
			// assert the invalid header is equal to the random string we passed
			// in previously as the invalid header.
			errors.As(lastEntry.Context[0].Interface.(error), &errRecv) &&
			strings.Contains(lastEntry.Context[0].Interface.(error).Error(), randString.String()) {
			return true
		}
		return false
	}, "poller should reject segment")
}

func TestSocketReadIrrecoverableNetError(t *testing.T) {
	_, p, recordedLogs := createAndOptionallyStartPoller(t, false)
	// close the actual socket because we are going to mock it out below
	p.(*poller).udpSock.Close()

	randErrStr, _ := uuid.NewRandom()
	p.(*poller).udpSock = &mockSocketConn{
		expectedOutput: []byte("dontCare"),
		expectedError: &mockNetError{
			mockErrStr: randErrStr.String(),
		},
	}

	p.Start(context.Background())

	testutil.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		lastEntry := logs[len(logs)-1]
		var errIrrecv *internalErr.ErrIrrecoverable
		if strings.Contains(lastEntry.Message, "irrecoverable socket read error. Exiting poller") &&
			lastEntry.Context[0].Type == zapcore.ErrorType &&
			errors.As(lastEntry.Context[0].Interface.(error), &errIrrecv) &&
			strings.Compare(errors.Unwrap(lastEntry.Context[0].Interface.(error)).Error(), randErrStr.String()) == 0 {
			return true
		}
		return false
	}, "poller should exit due to irrecoverable net read error")
}

func TestSocketReadTemporaryNetError(t *testing.T) {
	_, p, recordedLogs := createAndOptionallyStartPoller(t, false)
	// close the actual socket because we are going to mock it out below
	p.(*poller).udpSock.Close()

	randErrStr, _ := uuid.NewRandom()
	p.(*poller).udpSock = &mockSocketConn{
		expectedOutput: []byte("dontCare"),
		expectedError: &mockNetError{
			mockErrStr: randErrStr.String(),
			temporary:  true,
		},
	}

	p.Start(context.Background())

	testutil.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		lastEntry := logs[len(logs)-1]
		var errRecv *internalErr.ErrRecoverable
		if len(logs) > 0 &&
			strings.Contains(lastEntry.Message, "recoverable socket read error") &&
			lastEntry.Context[0].Type == zapcore.ErrorType &&
			errors.As(lastEntry.Context[0].Interface.(error), &errRecv) &&
			strings.Compare(errors.Unwrap(lastEntry.Context[0].Interface.(error)).Error(), randErrStr.String()) == 0 {
			return true
		}
		return false
	}, "poller should encounter net read error")
}

func TestSocketGenericReadError(t *testing.T) {
	_, p, recordedLogs := createAndOptionallyStartPoller(t, false)
	// close the actual socket because we are going to mock it out below
	p.(*poller).udpSock.Close()

	randErrStr, _ := uuid.NewRandom()
	p.(*poller).udpSock = &mockSocketConn{
		expectedOutput: []byte("dontCare"),
		expectedError: &mockGenericErr{
			mockErrStr: randErrStr.String(),
		},
	}

	p.Start(context.Background())

	testutil.WaitFor(t, func() bool {
		logs := recordedLogs.All()
		lastEntry := logs[len(logs)-1]
		var errRecv *internalErr.ErrRecoverable
		if strings.Contains(lastEntry.Message, "recoverable socket read error") &&
			lastEntry.Context[0].Type == zapcore.ErrorType &&
			errors.As(lastEntry.Context[0].Interface.(error), &errRecv) &&
			strings.Compare(errors.Unwrap(lastEntry.Context[0].Interface.(error)).Error(), randErrStr.String()) == 0 {
			return true
		}
		return false
	}, "poller should encounter generic socket read error")
}

type mockNetError struct {
	mockErrStr string
	temporary  bool
}

func (m *mockNetError) Error() string {
	return m.mockErrStr
}

func (m *mockNetError) Timeout() bool {
	return false
}

func (m *mockNetError) Temporary() bool {
	return m.temporary
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
	readCount      int
	mu             sync.Mutex
}

func (m *mockSocketConn) Read(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := copy(b, m.expectedOutput)
	if m.readCount > 0 {
		// intentionally slow to prevent a busy loop during any unit tests
		// that involve the poll() function
		time.Sleep(5 * time.Second)
	}
	m.readCount++
	return copied, m.expectedError
}

func (m *mockSocketConn) Close() error { return nil }

func createAndOptionallyStartPoller(t *testing.T, start bool) (string, Poller, *observer.ObservedLogs) {
	addr, err := findAvailableAddress()
	assert.NoError(t, err, "there should be address available")

	logger, recorded := logSetup()
	poller, err := New(&Config{
		Transport:          Transport,
		Endpoint:           addr,
		NumOfPollerToStart: 2,
	}, logger)
	assert.NoError(t, err, "receiver should be created")

	if start {
		poller.Start(context.Background())
	}
	return addr, poller, recorded
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
