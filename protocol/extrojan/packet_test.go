package extrojan

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	transportExtrojan "github.com/sagernet/sing-box/transport/extrojan"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestPacketInstallDoesNotLoseConcurrentDeadline(t *testing.T) {
	packetConn := &blockingDeadlinePacketConn{
		firstDeadline: make(chan struct{}),
		releaseFirst:  make(chan struct{}),
	}
	conn := &resumablePacketConn{
		cancel:  func() {},
		opening: true,
		wake:    make(chan struct{}),
	}

	installDone := make(chan error, 1)
	go func() {
		installed, err := conn.finishOpen(packetConn)
		if err == nil && !installed {
			err = net.ErrClosed
		}
		installDone <- err
	}()
	<-packetConn.firstDeadline

	deadline := time.Now().Add(time.Minute)
	setStarted := make(chan struct{})
	setDone := make(chan error, 1)
	go func() {
		close(setStarted)
		setDone <- conn.SetDeadline(deadline)
	}()
	<-setStarted
	select {
	case err := <-setDone:
		t.Fatalf("SetDeadline bypassed the in-progress install: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(packetConn.releaseFirst)
	if err := <-installDone; err != nil {
		t.Fatal(err)
	}
	if err := <-setDone; err != nil {
		t.Fatal(err)
	}
	if actual := packetConn.lastDeadline(); !actual.Equal(deadline) {
		t.Fatalf("installed packet connection kept stale deadline %v, want %v", actual, deadline)
	}
}

func TestOutboundCloseUnblocksResumablePacketRead(t *testing.T) {
	client, err := transportExtrojan.NewClient(
		transportExtrojan.DefaultConfig(),
		trojan.Key("packet-close-test"),
		func(context.Context) (net.Conn, error) {
			return nil, net.ErrClosed
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	outbound := &Outbound{
		client:  client,
		packets: make(map[*resumablePacketConn]struct{}),
	}
	underlying := &closedReadPacketConn{readStarted: make(chan struct{})}
	packetConn := newResumablePacketConn(
		context.Background(),
		outbound,
		M.ParseSocksaddr("127.0.0.1:53"),
		underlying,
	)
	if !outbound.registerPacketConn(packetConn) {
		t.Fatal("outbound rejected packet connection before close")
	}

	readResult := make(chan error, 1)
	go func() {
		var payload [1]byte
		_, _, readErr := packetConn.ReadFrom(payload[:])
		readResult <- readErr
	}()
	<-underlying.readStarted

	if err = outbound.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case readErr := <-readResult:
		if !errors.Is(readErr, net.ErrClosed) {
			t.Fatalf("blocked packet read returned %v, want net.ErrClosed", readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Outbound.Close did not unblock the resumable packet read")
	}
}

func TestResumablePacketReaderPreservesShortBufferError(t *testing.T) {
	underlying := &shortBufferPacketConn{}
	packetConn := newResumablePacketConn(
		context.Background(),
		nil,
		M.ParseSocksaddr("127.0.0.1:53"),
		underlying,
	)
	defer packetConn.Close()
	buffer := buf.NewSize(1)
	defer buffer.Release()

	_, err := packetConn.ReadPacket(buffer)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("small packet buffer returned %v, want io.ErrShortBuffer", err)
	}
	if underlying.readFromCalled {
		t.Fatal("stable packet wrapper bypassed the packet-aware reader and silently truncated the datagram")
	}
}

type blockingDeadlinePacketConn struct {
	access        sync.Mutex
	deadlines     []time.Time
	firstDeadline chan struct{}
	releaseFirst  chan struct{}
	firstOnce     sync.Once
}

type closedReadPacketConn struct {
	readStarted chan struct{}
	readOnce    sync.Once
}

type shortBufferPacketConn struct {
	readFromCalled bool
}

func (c *shortBufferPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if buffer.FreeLen() < 2 {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, _ = buffer.Write([]byte{1, 2})
	return M.ParseSocksaddr("127.0.0.1:53"), nil
}

func (c *shortBufferPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	c.readFromCalled = true
	return copy(payload, []byte{1, 2}), &net.UDPAddr{}, nil
}

func (c *shortBufferPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (c *shortBufferPacketConn) Close() error {
	return nil
}

func (c *shortBufferPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *shortBufferPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (c *shortBufferPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *shortBufferPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *closedReadPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.readOnce.Do(func() {
		close(c.readStarted)
	})
	return 0, nil, net.ErrClosed
}

func (c *closedReadPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (c *closedReadPacketConn) Close() error {
	return nil
}

func (c *closedReadPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *closedReadPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (c *closedReadPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *closedReadPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *blockingDeadlinePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *blockingDeadlinePacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (c *blockingDeadlinePacketConn) Close() error {
	return nil
}

func (c *blockingDeadlinePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *blockingDeadlinePacketConn) SetDeadline(deadline time.Time) error {
	first := false
	c.firstOnce.Do(func() {
		first = true
		close(c.firstDeadline)
	})
	if first {
		<-c.releaseFirst
	}
	c.access.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.access.Unlock()
	return nil
}

func (c *blockingDeadlinePacketConn) SetReadDeadline(deadline time.Time) error {
	return c.SetDeadline(deadline)
}

func (c *blockingDeadlinePacketConn) SetWriteDeadline(deadline time.Time) error {
	return c.SetDeadline(deadline)
}

func (c *blockingDeadlinePacketConn) lastDeadline() time.Time {
	c.access.Lock()
	defer c.access.Unlock()
	if len(c.deadlines) == 0 {
		return time.Time{}
	}
	return c.deadlines[len(c.deadlines)-1]
}
