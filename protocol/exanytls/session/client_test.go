package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	commonAtomic "github.com/sagernet/sing/common/atomic"
)

func TestClientPreservesAnyTLSSessionPoolSemantics(t *testing.T) {
	var clientPadding commonAtomic.TypedValue[*padding.PaddingFactory]
	var serverPadding commonAtomic.TypedValue[*padding.PaddingFactory]
	if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &clientPadding) ||
		!padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &serverPadding) {
		t.Fatal("failed to initialize AnyTLS padding")
	}

	var dialCount atomic.Int32
	client := NewClient(context.Background(), discardLogger{}, func(ctx context.Context) (net.Conn, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		clientConn, serverConn := net.Pipe()
		dialCount.Add(1)
		server := NewServerSession(serverConn, func(stream *Stream) {
			if err := stream.HandshakeSuccess(); err != nil {
				_ = stream.Close()
				return
			}
			_, _ = io.Copy(stream, stream)
			_ = stream.Close()
		}, &serverPadding, discardLogger{}, Options{})
		go server.Run()
		return clientConn, nil
	}, &clientPadding, ClientOptions{
		IdleSessionCheckInterval: time.Hour,
		IdleSessionTimeout:       time.Hour,
		MinIdleSession:           1,
	})
	t.Cleanup(func() { _ = client.Close() })

	first := createPooledEchoStream(t, client, "first")
	second := createPooledEchoStream(t, client, "second")
	if count := dialCount.Load(); count != 2 {
		t.Fatalf("two concurrent streams created %d sessions, want 2", count)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	waitForPoolState(t, client, 2, 2)

	reused := createPooledEchoStream(t, client, "reused")
	if count := dialCount.Load(); count != 2 {
		t.Fatalf("an idle session was not reused: created %d sessions", count)
	}
	if err := reused.Close(); err != nil {
		t.Fatal(err)
	}
	waitForPoolState(t, client, 2, 2)

	client.idleSessionLock.Lock()
	client.idleSession.ForEach(func(_ uint64, pooledSession *Session) {
		pooledSession.idleSince = time.Time{}
	})
	client.idleSessionLock.Unlock()
	client.idleCleanupExpTime(time.Now())
	waitForPoolState(t, client, 1, 1)

	retained := createPooledEchoStream(t, client, "retained")
	if count := dialCount.Load(); count != 2 {
		t.Fatalf("min_idle_session did not retain an idle session: created %d sessions", count)
	}
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
}

func createPooledEchoStream(t *testing.T, client *Client, payload string) *Stream {
	t.Helper()
	stream, err := client.CreateStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	content := []byte(payload)
	if _, err = stream.Write(content); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(content))
	if _, err = io.ReadFull(stream, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, content) {
		t.Fatalf("echo payload changed: got %q, want %q", received, content)
	}
	return stream
}

func waitForPoolState(t *testing.T, client *Client, idleCount int, sessionCount int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		client.idleSessionLock.Lock()
		actualIdleCount := client.idleSession.Len()
		client.idleSessionLock.Unlock()
		client.sessionsLock.Lock()
		actualSessionCount := len(client.sessions)
		client.sessionsLock.Unlock()
		if actualIdleCount == idleCount && actualSessionCount == sessionCount {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pool state is idle=%d sessions=%d, want idle=%d sessions=%d", actualIdleCount, actualSessionCount, idleCount, sessionCount)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
