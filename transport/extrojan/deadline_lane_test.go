package extrojan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"
)

func TestLaneWriteSupportsTransportWithoutWriteDeadline(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	session := newTestSession(t, DefaultConfig())
	defer session.CloseWithError(net.ErrClosed)
	testLane := newLane(1, &unsupportedDeadlineConn{Conn: clientConn}, session)
	frame, err := EncodeFrame(FramePing, []byte("deadline-test"), session.config.MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}

	receivedCh := make(chan []byte, 1)
	errorCh := make(chan error, 1)
	go func() {
		received := make([]byte, len(frame))
		if _, readErr := io.ReadFull(serverConn, received); readErr != nil {
			errorCh <- readErr
			return
		}
		receivedCh <- received
	}()

	if err = testLane.write(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case readErr := <-errorCh:
		t.Fatal(readErr)
	case received := <-receivedCh:
		if !bytes.Equal(received, frame) {
			t.Fatal("lane write changed the encoded frame")
		}
	}
}

func TestLaneWriteTimesOutWithoutNativeWriteDeadline(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	config := DefaultConfig()
	config.HeartbeatInterval = 10 * time.Millisecond
	config.LinkTimeout = 50 * time.Millisecond
	session := newTestSession(t, config)
	defer session.CloseWithError(net.ErrClosed)
	testLane := newLane(1, &unsupportedDeadlineConn{Conn: clientConn}, session)
	frame, err := EncodeFrame(FramePing, []byte("blocked-write"), session.config.MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	err = testLane.write(frame)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected write deadline error, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocked write exceeded timeout budget: %v", elapsed)
	}
}

func TestWebSocketBlockedWriteForceClosesRawCarrier(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	websocketConn := v2raywebsocket.NewConn(clientConn, nil, ws.StateClientSide)
	conn := PrepareHandshakeConn(websocketConn)

	writerExited := make(chan struct{})
	started := time.Now()
	err := writeWithDeadline(conn, time.Now().Add(50*time.Millisecond), func() error {
		defer close(writerExited)
		_, writeErr := conn.Write([]byte("blocked-websocket-write"))
		return writeErr
	})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected WebSocket write deadline error, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("WebSocket force close exceeded link timeout budget: %v", elapsed)
	}
	select {
	case <-writerExited:
	case <-time.After(time.Second):
		t.Fatal("raw WebSocket carrier close did not unblock the writer")
	}
}

func TestEarlyWebSocketUpgradeHonorsExtrojanHandshakeDeadline(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	dialer := &singleConnectionDialer{connection: clientConn}
	transport, err := v2raywebsocket.NewClient(
		context.Background(),
		dialer,
		M.ParseSocksaddrHostPort("example.com", 80),
		option.V2RayWebsocketOptions{
			Path:         "/extrojan",
			MaxEarlyData: 1024,
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	handshakeDeadline := time.Now().Add(50 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), handshakeDeadline)
	defer cancel()
	earlyConn, err := transport.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn := PrepareHandshakeConn(earlyConn)
	writerExited := make(chan struct{})
	started := time.Now()
	err = writeWithDeadline(conn, handshakeDeadline, func() error {
		defer close(writerExited)
		_, writeErr := conn.Write([]byte("early-data"))
		return writeErr
	})
	if !isTimeout(err) {
		t.Fatalf("expected early WebSocket upgrade timeout, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("early WebSocket upgrade exceeded handshake budget: %v", elapsed)
	}
	select {
	case <-writerExited:
	case <-time.After(time.Second):
		t.Fatal("early WebSocket upgrade remained blocked after its context deadline")
	}
}

type singleConnectionDialer struct {
	connection net.Conn
}

func (d *singleConnectionDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	if d.connection == nil {
		return nil, net.ErrClosed
	}
	connection := d.connection
	d.connection = nil
	return connection, nil
}

func (d *singleConnectionDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

var _ N.Dialer = (*singleConnectionDialer)(nil)
