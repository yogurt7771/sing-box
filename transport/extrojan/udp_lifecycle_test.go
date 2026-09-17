package extrojan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/trojan"
	M "github.com/sagernet/sing/common/metadata"
)

func TestUDPIdleTimeoutClosesAssociationAndUnusedSession(t *testing.T) {
	config := DefaultConfig()
	config.UDPIdleTimeout = 50 * time.Millisecond
	session := newTestSession(t, config)
	packetConn := installTestPacketConn(session, 1)
	packetConn.startIdleTimer()

	waitClosed(t, packetConn.closed, time.Second, "UDP association idle timeout")
	if !errors.Is(packetConn.err(), ErrUDPIdleTimeout) {
		t.Fatalf("unexpected UDP close error: %v", packetConn.err())
	}
	waitClosed(t, session.Done(), time.Second, "unused session cleanup")
}

func TestUDPActivityRefreshesIdleTimeout(t *testing.T) {
	config := DefaultConfig()
	config.UDPIdleTimeout = 100 * time.Millisecond
	session, err := NewSession(SessionOptions{
		Config: config,
		Server: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.CloseWithError(net.ErrClosed)
	packetConn := installTestPacketConn(session, 1)
	packetConn.startIdleTimer()

	time.Sleep(60 * time.Millisecond)
	packetConn.deliver(packetConn.destination, []byte("activity"))
	select {
	case <-packetConn.closed:
		t.Fatal("UDP association expired before the refreshed idle deadline")
	case <-time.After(60 * time.Millisecond):
	}
	waitClosed(t, packetConn.closed, time.Second, "refreshed UDP idle timeout")
}

func TestOutgoingUDPActivityRefreshesIdleTimeout(t *testing.T) {
	config := DefaultConfig()
	config.UDPIdleTimeout = 100 * time.Millisecond
	session, err := NewSession(SessionOptions{
		Config: config,
		Server: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.CloseWithError(net.ErrClosed)
	packetConn := installTestPacketConn(session, 1)
	packetConn.startIdleTimer()

	time.Sleep(60 * time.Millisecond)
	if err = packetConn.writePacket([]byte("activity"), packetConn.destination); err != nil {
		t.Fatal(err)
	}
	select {
	case <-packetConn.closed:
		t.Fatal("UDP association expired before the outgoing activity deadline")
	case <-time.After(60 * time.Millisecond):
	}
	waitClosed(t, packetConn.closed, time.Second, "outgoing UDP idle timeout")
}

func TestUDPIdleCleanupWaitsForRetainedTCPStream(t *testing.T) {
	config := DefaultConfig()
	config.UDPIdleTimeout = 50 * time.Millisecond
	session := newTestSession(t, config)
	release, err := session.RetainStream()
	if err != nil {
		t.Fatal(err)
	}
	packetConn := installTestPacketConn(session, 1)
	packetConn.startIdleTimer()

	waitClosed(t, packetConn.closed, time.Second, "UDP association idle timeout")
	select {
	case <-session.Done():
		t.Fatal("UDP idle cleanup closed a session with a retained TCP stream")
	case <-time.After(75 * time.Millisecond):
	}
	release()
	waitClosed(t, session.Done(), time.Second, "session cleanup after TCP release")
}

func TestUDPIdleOptionDoesNotCloseTCPOnlySession(t *testing.T) {
	config := DefaultConfig()
	config.UDPIdleTimeout = 50 * time.Millisecond
	session := newTestSession(t, config)
	defer session.CloseWithError(net.ErrClosed)
	release, err := session.RetainStream()
	if err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-session.Done():
		t.Fatal("UDP idle option closed a session that had never carried UDP")
	case <-time.After(75 * time.Millisecond):
	}
}

func TestLateUDPOpenCannotOutliveClosedServerSession(t *testing.T) {
	config := DefaultConfig()
	udpOpened := make(chan struct{}, 1)
	session, err := NewSession(SessionOptions{
		Config: config,
		Server: true,
		OnUDPOpen: func(context.Context, *PacketConn, M.Socksaddr) {
			udpOpened <- struct{}{}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	session.CloseWithError(net.ErrClosed)

	payload, err := EncodeUDPOpen(1, M.ParseSocksaddr("127.0.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	if err = session.handleUDPOpen(payload); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late UDP_OPEN returned %v, want net.ErrClosed", err)
	}
	session.packetAccess.Lock()
	packetCount := len(session.packets)
	session.packetAccess.Unlock()
	if packetCount != 0 {
		t.Fatalf("late UDP_OPEN created %d association(s) after session close", packetCount)
	}
	select {
	case <-udpOpened:
		t.Fatal("late UDP_OPEN invoked the upstream callback after session close")
	default:
	}
}

func TestStaleResumeTimerCannotClearReplacementTimer(t *testing.T) {
	session := newTestSession(t, DefaultConfig())
	defer session.CloseWithError(net.ErrClosed)
	replacementTimer := time.AfterFunc(time.Hour, func() {})
	defer replacementTimer.Stop()

	session.laneAccess.Lock()
	session.resumeEpoch = 2
	session.resumeTimer = replacementTimer
	session.laneAccess.Unlock()
	session.expireResume(1)

	session.laneAccess.Lock()
	actualTimer := session.resumeTimer
	resumeExpired := session.resumeExpired
	session.laneAccess.Unlock()
	if actualTimer != replacementTimer {
		t.Fatal("stale resume timer cleared the replacement timer")
	}
	if resumeExpired {
		t.Fatal("stale resume timer expired the current session")
	}
}

func TestLaneRotationReplacesOnlyOneCarrierAndRefillsPool(t *testing.T) {
	config := DefaultConfig()
	config.Connections = 2
	config.HeartbeatInterval = 20 * time.Millisecond
	config.LinkTimeout = 500 * time.Millisecond
	config.ResumeTimeout = 2 * time.Second
	config.ReconnectInitialDelay = 10 * time.Millisecond
	config.ReconnectMaxDelay = 50 * time.Millisecond
	config.LaneRotationInterval = 100 * time.Millisecond

	server, err := NewServer(ServerOptions{Config: config})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	key := trojan.Key("rotation-password")
	var dialCount atomic.Int32
	client, err := NewClient(config, key, func(context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		dialCount.Add(1)
		go serveTestCarrier(server, serverConn, key)
		return clientConn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	session, err := client.OpenSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return session.LaneCount() == config.Connections
	}, "initial lane pool")
	packetConn := installTestPacketConn(session, 9)
	defer packetConn.Close()

	waitFor(t, 2*time.Second, func() bool {
		return dialCount.Load() >= 3 && session.LaneCount() == config.Connections
	}, "rotated lane replacement")
	if count := session.LaneCount(); count != config.Connections {
		t.Fatalf("rotation changed lane pool size: got %d, want %d", count, config.Connections)
	}
}

func installTestPacketConn(session *Session, associationID uint64) *PacketConn {
	packetConn := newPacketConn(session, associationID, M.ParseSocksaddr("127.0.0.1:53"))
	session.packetAccess.Lock()
	session.packets[associationID] = packetConn
	session.udpLifecycle = true
	session.packetAccess.Unlock()
	return packetConn
}

func serveTestCarrier(server *Server, conn net.Conn, expectedKey [trojan.KeyLength]byte) {
	header := make([]byte, trojan.KeyLength+len(trojan.CRLF)+1)
	if _, err := io.ReadFull(conn, header); err != nil {
		_ = conn.Close()
		return
	}
	if !bytes.Equal(header[:trojan.KeyLength], expectedKey[:]) ||
		!bytes.Equal(header[trojan.KeyLength:trojan.KeyLength+len(trojan.CRLF)], trojan.CRLF) {
		_ = conn.Close()
		return
	}
	var err error
	switch header[len(header)-1] {
	case CommandOpen:
		err = server.HandleOpen(context.Background(), conn, 0, M.ParseSocksaddr("127.0.0.1:12345"))
	case CommandJoin:
		err = server.HandleJoin(context.Background(), conn, 0)
	default:
		err = errors.New("unexpected carrier command")
	}
	if err != nil {
		_ = conn.Close()
	}
}

func waitClosed(t *testing.T, done <-chan struct{}, timeout time.Duration, description string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}
