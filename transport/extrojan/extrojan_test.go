package extrojan

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestClientTreatsOpenWriteResetAsLegacy(t *testing.T) {
	config := DefaultConfig()
	config.LegacyProbeTimeout = time.Second
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	client, err := NewClient(config, trojan.Key("password"), func(context.Context) (net.Conn, error) {
		return clientSide, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	readDone := make(chan error, 1)
	go func() {
		header := make([]byte, trojan.KeyLength+len(trojan.CRLF)+1)
		_, readErr := io.ReadFull(serverSide, header)
		_ = serverSide.Close()
		readDone <- readErr
	}()
	_, err = client.OpenSession(context.Background())
	if !errors.Is(err, ErrLegacyServer) {
		t.Fatalf("expected legacy fallback error, got %v", err)
	}
	if readErr := <-readDone; readErr != nil {
		t.Fatal(readErr)
	}
}

func TestHandshakeDeadlineSupportsFramedTransport(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	unsupported := &unsupportedDeadlineConn{Conn: clientSide}
	prepared := PrepareHandshakeConn(unsupported)
	defer prepared.Close()
	if prepared == unsupported {
		t.Fatal("connection requiring an additional deadline was not wrapped")
	}
	if err := setHandshakeDeadline(prepared, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := setHandshakeDeadline(prepared, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

type unsupportedDeadlineConn struct {
	net.Conn
}

func (c *unsupportedDeadlineConn) SetDeadline(time.Time) error {
	return os.ErrInvalid
}

func (c *unsupportedDeadlineConn) SetReadDeadline(time.Time) error {
	return os.ErrInvalid
}

func (c *unsupportedDeadlineConn) SetWriteDeadline(time.Time) error {
	return os.ErrInvalid
}

func (c *unsupportedDeadlineConn) NeedAdditionalReadDeadline() bool {
	return true
}

type dropFrameConn struct {
	net.Conn
	frameType byte
}

func (c *dropFrameConn) Write(payload []byte) (int, error) {
	if len(payload) >= 5 &&
		int(binary.BigEndian.Uint32(payload[:4])) == len(payload)-4 &&
		payload[4] == c.frameType {
		return len(payload), nil
	}
	return c.Conn.Write(payload)
}

func TestReliableWriteFailsAfterSessionClose(t *testing.T) {
	session := newTestSession(t, DefaultConfig())
	session.CloseWithError(net.ErrClosed)
	if _, err := session.reliable.Write([]byte("must fail")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed error, got %v", err)
	}
	session.reliable.access.Lock()
	pending := len(session.reliable.sendPending)
	session.reliable.access.Unlock()
	if pending != 0 {
		t.Fatalf("closed stream retained %d new segments", pending)
	}
}

func TestReliableSegmentLimitStillAcceptsMissingPrefix(t *testing.T) {
	config := DefaultConfig()
	config.MaxStreamSegments = 16
	session := newTestSession(t, config)
	defer session.CloseWithError(net.ErrClosed)

	for offset := uint64(1); offset <= 16; offset++ {
		if _, err := session.reliable.receive(offset, []byte{byte(offset)}); err != nil {
			t.Fatal(err)
		}
	}
	next, err := session.reliable.receive(0, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	if next != 16 {
		t.Fatalf("missing prefix did not advance receive window: got %d", next)
	}
	received := make([]byte, 16)
	if _, err = io.ReadFull(session.reliable, received); err != nil {
		t.Fatal(err)
	}
	for index, value := range received {
		if value != byte(index) {
			t.Fatalf("received[%d] = %d", index, value)
		}
	}
	next, err = session.reliable.receive(16, []byte{16})
	if err != nil {
		t.Fatal(err)
	}
	if next != 17 {
		t.Fatalf("receive window remained stalled at %d", next)
	}
}

func TestUDPQueueHasSessionByteLimitAndNoSilentTruncation(t *testing.T) {
	config := DefaultConfig()
	config.MaxUDPQueueBytes = DefaultMaxUDPPayload
	session := newTestSession(t, config)
	defer session.CloseWithError(net.ErrClosed)
	packetConn := newPacketConn(session, 1, M.ParseSocksaddr("127.0.0.1:53"))

	payload := bytes.Repeat([]byte{0x5a}, 40000)
	packetConn.deliver(packetConn.destination, payload)
	packetConn.deliver(packetConn.destination, payload)
	if queued := len(packetConn.receive); queued != 1 {
		t.Fatalf("session byte limit admitted %d packets, want 1", queued)
	}
	if queuedBytes := session.udpQueuedBytes.Load(); queuedBytes != int64(len(payload)) {
		t.Fatalf("queued bytes = %d, want %d", queuedBytes, len(payload))
	}

	smallBuffer := buf.NewSize(64)
	defer smallBuffer.Release()
	if _, err := packetConn.ReadPacket(smallBuffer); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("expected short-buffer error, got %v", err)
	}
	if smallBuffer.Len() != 0 {
		t.Fatalf("oversized datagram was partially copied: %d bytes", smallBuffer.Len())
	}
	if queuedBytes := session.udpQueuedBytes.Load(); queuedBytes != 0 {
		t.Fatalf("dequeued bytes were not released: %d", queuedBytes)
	}
}

func TestUDPCloseRemainsPendingUntilAcknowledged(t *testing.T) {
	session := newTestSession(t, DefaultConfig())
	defer session.CloseWithError(net.ErrClosed)
	packetConn := newPacketConn(session, 7, M.ParseSocksaddr("127.0.0.1:53"))
	session.packets[7] = packetConn

	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}
	session.packetAccess.Lock()
	_, pending := session.pendingPacketCloses[7]
	session.packetAccess.Unlock()
	if !pending {
		t.Fatal("UDP close was not retained for retransmission")
	}
	if err := session.handleFrame(nil, FrameUDPCloseACK, EncodeUint64(7)); err != nil {
		t.Fatal(err)
	}
	session.packetAccess.Lock()
	_, pending = session.pendingPacketCloses[7]
	_, tombstoned := session.packetTombstones[7]
	session.packetAccess.Unlock()
	if pending {
		t.Fatal("UDP close remained pending after acknowledgement")
	}
	if !tombstoned {
		t.Fatal("acknowledged UDP close did not retain a reorder tombstone")
	}
}

func TestUDPOpenDoesNotRecreateClosingAssociation(t *testing.T) {
	config := DefaultConfig()
	var opened atomic.Int32
	session, err := NewSession(SessionOptions{
		Config: config,
		Server: true,
		OnUDPOpen: func(context.Context, *PacketConn, M.Socksaddr) {
			opened.Add(1)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.CloseWithError(net.ErrClosed)

	const associationID = 41
	session.packetAccess.Lock()
	session.pendingPacketCloses[associationID] = time.Time{}
	session.packetAccess.Unlock()
	payload, err := EncodeUDPOpen(associationID, M.ParseSocksaddrHostPort("udp.example", 53))
	if err != nil {
		t.Fatal(err)
	}
	if err = session.handleUDPOpen(payload); err != nil {
		t.Fatal(err)
	}
	session.packetAccess.Lock()
	packetConn := session.packets[associationID]
	_, closing := session.pendingPacketCloses[associationID]
	session.packetAccess.Unlock()
	if packetConn != nil || !closing || opened.Load() != 0 {
		t.Fatal("duplicate UDP_OPEN recreated an association with a pending close")
	}
}

func TestRemoteUDPCloseTombstoneRejectsStaleOpen(t *testing.T) {
	config := DefaultConfig()
	var opened atomic.Int32
	session, err := NewSession(SessionOptions{
		Config: config,
		Server: true,
		OnUDPOpen: func(context.Context, *PacketConn, M.Socksaddr) {
			opened.Add(1)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.CloseWithError(net.ErrClosed)

	const associationID = 42
	destination := M.ParseSocksaddrHostPort("udp.example", 53)
	packetConn := newPacketConn(session, associationID, destination)
	session.packetAccess.Lock()
	session.packets[associationID] = packetConn
	session.packetAccess.Unlock()

	if err = session.handleFrame(nil, FrameUDPClose, EncodeUint64(associationID)); err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeUDPOpen(associationID, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = session.handleUDPOpen(payload); err != nil {
		t.Fatal(err)
	}

	session.packetAccess.Lock()
	recreated := session.packets[associationID]
	_, tombstoned := session.packetTombstones[associationID]
	session.packetAccess.Unlock()
	if recreated != nil || !tombstoned || opened.Load() != 0 {
		t.Fatal("stale cross-lane UDP_OPEN recreated a remotely closed association")
	}
}

func TestServerCloseBeforeOpenTombstoneRejectsReorderedOpen(t *testing.T) {
	config := DefaultConfig()
	var opened atomic.Int32
	session, err := NewSession(SessionOptions{
		Config: config,
		Server: true,
		OnUDPOpen: func(context.Context, *PacketConn, M.Socksaddr) {
			opened.Add(1)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.CloseWithError(net.ErrClosed)

	const associationID = 43
	if err = session.handleFrame(nil, FrameUDPClose, EncodeUint64(associationID)); err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeUDPOpen(associationID, M.ParseSocksaddrHostPort("udp.example", 53))
	if err != nil {
		t.Fatal(err)
	}
	if err = session.handleUDPOpen(payload); err != nil {
		t.Fatal(err)
	}

	session.packetAccess.Lock()
	recreated := session.packets[associationID]
	_, tombstoned := session.packetTombstones[associationID]
	session.packetAccess.Unlock()
	if recreated != nil || !tombstoned || opened.Load() != 0 {
		t.Fatal("UDP_OPEN reordered after an earlier CLOSE created an upstream association")
	}
}

func TestCanceledUDPOpenReliablyClosesServerAssociation(t *testing.T) {
	config := DefaultConfig()
	config.HeartbeatInterval = 100 * time.Millisecond
	config.LinkTimeout = 2 * time.Second
	config.RetransmitInterval = 20 * time.Millisecond
	clientSession, err := NewSession(SessionOptions{
		Config: config,
		Server: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.CloseWithError(net.ErrClosed)
	serverOpened := make(chan struct{}, 1)
	serverSession, err := NewSession(SessionOptions{
		Config: config,
		Server: true,
		OnUDPOpen: func(context.Context, *PacketConn, M.Socksaddr) {
			select {
			case serverOpened <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.CloseWithError(net.ErrClosed)

	clientCarrier, serverCarrier := net.Pipe()
	if err = clientSession.AddLane(1, clientCarrier); err != nil {
		t.Fatal(err)
	}
	if err = serverSession.AddLane(1, &dropFrameConn{Conn: serverCarrier, frameType: FrameUDPOpenACK}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = clientSession.OpenPacket(ctx, M.ParseSocksaddrHostPort("udp.example", 53))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("UDP open returned %v, want context deadline", err)
	}
	select {
	case <-serverOpened:
	case <-time.After(time.Second):
		t.Fatal("server never created the association whose ACK was dropped")
	}
	waitFor(t, time.Second, func() bool {
		serverSession.packetAccess.Lock()
		defer serverSession.packetAccess.Unlock()
		return len(serverSession.packets) == 0
	}, "server association cleanup after canceled UDP open")
	waitFor(t, time.Second, func() bool {
		clientSession.packetAccess.Lock()
		defer clientSession.packetAccess.Unlock()
		_, pendingClose := clientSession.pendingPacketCloses[1]
		_, tombstoned := clientSession.packetTombstones[1]
		return !pendingClose && tombstoned
	}, "client UDP close acknowledgement")
}

func TestUDPCloseTombstonesAreBoundedAndExpire(t *testing.T) {
	config := DefaultConfig()
	config.MaxUDPAssociations = 2
	session := newTestSession(t, config)
	defer session.CloseWithError(net.ErrClosed)
	now := time.Now()

	session.packetAccess.Lock()
	session.recordPacketTombstoneLocked(1, now)
	session.recordPacketTombstoneLocked(2, now.Add(time.Millisecond))
	session.recordPacketTombstoneLocked(3, now.Add(2*time.Millisecond))
	tombstoneCount := len(session.packetTombstones)
	_, newestRetained := session.packetTombstones[3]
	for associationID := range session.packetTombstones {
		session.packetTombstones[associationID] = now.Add(-time.Millisecond)
	}
	session.purgePacketTombstonesLocked(now)
	expiredCount := len(session.packetTombstones)
	session.packetAccess.Unlock()

	if tombstoneCount != config.MaxUDPAssociations || !newestRetained {
		t.Fatalf("UDP tombstones were not bounded while retaining the newest close: count=%d newest=%v", tombstoneCount, newestRetained)
	}
	if expiredCount != 0 {
		t.Fatalf("expired UDP tombstones were not purged: %d remain", expiredCount)
	}
}

func TestReliableFINRejectsPendingDataBeyondOffset(t *testing.T) {
	session := newTestSession(t, DefaultConfig())
	defer session.CloseWithError(net.ErrClosed)
	if _, err := session.reliable.receive(64, []byte("beyond-fin")); err != nil {
		t.Fatal(err)
	}
	if _, err := session.reliable.receiveFIN(68); err == nil {
		t.Fatal("FIN accepted pending data beyond its final offset")
	}
}

func TestFrameBoundsAndUnknownTypeAreRejected(t *testing.T) {
	for _, length := range []uint32{0, DefaultMaxFrameSize + 1} {
		var content bytes.Buffer
		if err := binary.Write(&content, binary.BigEndian, length); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadFrame(&content, DefaultMaxFrameSize); err == nil {
			t.Fatalf("frame length %d was accepted", length)
		}
	}
	session := newTestSession(t, DefaultConfig())
	defer session.CloseWithError(net.ErrClosed)
	if err := session.handleFrame(nil, 0xff, nil); err == nil {
		t.Fatal("unknown frame type was accepted")
	}
}

func newTestSession(t *testing.T, config Config) *Session {
	t.Helper()
	session, err := NewSession(SessionOptions{
		Context: context.Background(),
		Config:  config,
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}
