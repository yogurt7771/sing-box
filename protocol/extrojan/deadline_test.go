package extrojan

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	transportExtrojan "github.com/sagernet/sing-box/transport/extrojan"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/ws"
)

func TestServerWebSocketTimeoutUnwrapsCloseCallbackCarrier(t *testing.T) {
	config := transportExtrojan.DefaultConfig()
	config.Connections = 1
	config.HeartbeatInterval = 10 * time.Millisecond
	config.LinkTimeout = 50 * time.Millisecond
	server, err := transportExtrojan.NewServer(transportExtrojan.ServerOptions{Config: config})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	clientConn := v2raywebsocket.NewConn(clientRaw, nil, ws.StateClientSide)
	serverConn := v2raywebsocket.NewConn(serverRaw, nil, ws.StateServerSide)
	callbackCalled := make(chan struct{}, 1)
	wrappedServerConn := &closeCallbackConn{
		Conn: transportExtrojan.PrepareHandshakeConn(serverConn),
		callback: func(error) {
			callbackCalled <- struct{}{}
		},
	}

	handleResult := make(chan error, 1)
	started := time.Now()
	go func() {
		handleResult <- server.HandleOpen(
			t.Context(),
			wrappedServerConn,
			0,
			M.ParseSocksaddr("127.0.0.1:12345"),
		)
	}()
	if _, err = clientConn.Write([]byte{transportExtrojan.ProtocolVersion, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}

	select {
	case handleErr := <-handleResult:
		if !errors.Is(handleErr, os.ErrDeadlineExceeded) {
			t.Fatalf("expected server response deadline error, got %v", handleErr)
		}
	case <-time.After(time.Second):
		t.Fatal("server WebSocket timeout used the graceful 15-second close path")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("server carrier force close exceeded link timeout budget: %v", elapsed)
	}
	select {
	case <-callbackCalled:
	case <-time.After(time.Second):
		t.Fatal("force-closing the raw carrier skipped the outer close callback")
	}
}
