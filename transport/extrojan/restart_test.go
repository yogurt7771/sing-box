package extrojan

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/trojan"
)

func TestJoinRejectionTerminality(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		status   byte
		terminal bool
	}{
		{"unsupported-version", StatusUnsupportedVersion, true},
		{"unauthorized", StatusUnauthorized, true},
		{"not-found", StatusNotFound, true},
		{"invalid-request", StatusInvalidRequest, true},
		{"resource-limit", StatusResourceLimit, false},
		{"unknown-future-status", 0xff, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := &joinRejectedError{status: testCase.status, message: testCase.name}
			if actual := isTerminalJoinRejection(err); actual != testCase.terminal {
				t.Fatalf("terminal=%v, want %v", actual, testCase.terminal)
			}
		})
	}
	if isTerminalJoinRejection(net.ErrClosed) {
		t.Fatal("transport failure was classified as a terminal JOIN rejection")
	}
}

func TestServerRestartRejectsStaleSessionWithoutResumeTimeout(t *testing.T) {
	config := restartTestConfig()
	config.ResumeTimeout = 5 * time.Second
	firstServer := newRestartTestServer(t, config)
	secondServer := newRestartTestServer(t, config)
	var activeServer atomic.Pointer[Server]
	activeServer.Store(firstServer)

	key := trojan.Key("server-restart-password")
	client := newRestartTestClient(t, config, key, &activeServer, nil)
	session, err := client.OpenSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return session.LaneCount() == config.Connections
	}, "initial lane pool")

	activeServer.Store(secondServer)
	restartedAt := time.Now()
	if err = firstServer.Close(); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, session.Done(), time.Second, "stale client session rejection")
	if elapsed := time.Since(restartedAt); elapsed >= config.ResumeTimeout {
		t.Fatalf("stale session waited for resume timeout: %v", elapsed)
	}
	var rejection *joinRejectedError
	if !errors.As(session.Err(), &rejection) {
		t.Fatalf("stale session closed with %v, want JOIN rejection", session.Err())
	}
	if rejection.status != StatusNotFound {
		t.Fatalf("stale session rejection status=%d, want %d", rejection.status, StatusNotFound)
	}

	freshSession, err := client.OpenSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return freshSession.LaneCount() == config.Connections && secondServer.SessionCount() == 1
	}, "fresh session after server restart")
}

func TestJoinNotFoundDoesNotKillSessionWithLiveLane(t *testing.T) {
	config := restartTestConfig()
	firstServer := newRestartTestServer(t, config)
	otherServer := newRestartTestServer(t, config)
	var activeServer atomic.Pointer[Server]
	activeServer.Store(firstServer)
	var dialCount atomic.Int32

	key := trojan.Key("rolling-backend-password")
	client := newRestartTestClient(t, config, key, &activeServer, &dialCount)
	session, err := client.OpenSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return session.LaneCount() == config.Connections
	}, "initial lane pool")
	initialDialCount := dialCount.Load()

	activeServer.Store(otherServer)
	session.laneAccess.Lock()
	var droppedLane *lane
	for _, candidate := range session.lanes {
		droppedLane = candidate
		break
	}
	session.laneAccess.Unlock()
	if droppedLane == nil {
		t.Fatal("missing lane to drop")
	}
	droppedLane.close()
	waitFor(t, time.Second, func() bool {
		return dialCount.Load() > initialDialCount
	}, "JOIN against backend without the session")
	if err = session.Err(); err != nil {
		t.Fatalf("live session was killed by another backend's rejection: %v", err)
	}
	if count := session.LaneCount(); count != 1 {
		t.Fatalf("lane count=%d, want one surviving lane", count)
	}

	activeServer.Store(firstServer)
	waitFor(t, time.Second, func() bool {
		return session.LaneCount() == config.Connections
	}, "lane refill on the session-owning backend")
}

func TestClientRestartOrphanExpiresAndReleasesSessionLimit(t *testing.T) {
	config := restartTestConfig()
	config.Connections = 1
	config.ResumeTimeout = 100 * time.Millisecond
	config.MaxSessionsPerUser = 1
	server := newRestartTestServer(t, config)
	var activeServer atomic.Pointer[Server]
	activeServer.Store(server)
	key := trojan.Key("client-restart-password")

	firstClient := newRestartTestClient(t, config, key, &activeServer, nil)
	if _, err := firstClient.OpenSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return server.SessionCount() == 1
	}, "server session before client restart")
	if err := firstClient.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return server.SessionCount() == 0
	}, "orphaned server session cleanup")

	secondClient := newRestartTestClient(t, config, key, &activeServer, nil)
	if _, err := secondClient.OpenSession(context.Background()); err != nil {
		t.Fatalf("replacement client could not use released session capacity: %v", err)
	}
}

func restartTestConfig() Config {
	config := DefaultConfig()
	config.Connections = 2
	config.ResumeTimeout = 2 * time.Second
	config.HeartbeatInterval = 20 * time.Millisecond
	config.LinkTimeout = 200 * time.Millisecond
	config.ReconnectInitialDelay = 10 * time.Millisecond
	config.ReconnectMaxDelay = 50 * time.Millisecond
	return config
}

func newRestartTestServer(t *testing.T, config Config) *Server {
	t.Helper()
	server, err := NewServer(ServerOptions{Config: config})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	return server
}

func newRestartTestClient(
	t *testing.T,
	config Config,
	key [trojan.KeyLength]byte,
	activeServer *atomic.Pointer[Server],
	dialCount *atomic.Int32,
) *Client {
	t.Helper()
	client, err := NewClient(config, key, func(context.Context) (net.Conn, error) {
		server := activeServer.Load()
		if server == nil {
			return nil, net.ErrClosed
		}
		clientConn, serverConn := net.Pipe()
		if dialCount != nil {
			dialCount.Add(1)
		}
		go serveTestCarrier(server, serverConn, key)
		return clientConn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}
