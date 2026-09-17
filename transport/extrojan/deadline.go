package extrojan

import (
	"errors"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio/deadline"
)

// PrepareHandshakeConn adds a read-deadline implementation for stream
// transports such as WebSocket, HTTP/2 and gRPC whose net.Conn adapters do not
// implement native deadlines.
func PrepareHandshakeConn(conn net.Conn) net.Conn {
	if deadline.NeedAdditionalReadDeadline(conn) {
		return deadline.NewConn(conn)
	}
	return conn
}

// setHandshakeDeadline bounds handshake reads. Handshake writes are bounded
// separately by writeWithDeadline because framed stream transports such as
// WebSocket do not implement SetWriteDeadline.
func setHandshakeDeadline(conn net.Conn, deadlineValue time.Time) error {
	return conn.SetReadDeadline(deadlineValue)
}

// writeWithDeadline uses the connection's native write deadline when
// available. For framed stream transports that reject write deadlines, it
// force-closes the underlying carrier when the timer expires.
func writeWithDeadline(conn net.Conn, deadlineValue time.Time, write func() error) error {
	if deadlineValue.IsZero() {
		return write()
	}
	err := conn.SetWriteDeadline(deadlineValue)
	if err == nil {
		writeErr := write()
		clearErr := conn.SetWriteDeadline(time.Time{})
		if writeErr != nil {
			return writeErr
		}
		return clearErr
	}
	if !errors.Is(err, os.ErrInvalid) {
		return err
	}

	wait := time.Until(deadlineValue)
	if wait <= 0 {
		forceCloseCarrier(conn)
		return os.ErrDeadlineExceeded
	}
	result := make(chan error, 1)
	go func() {
		result <- write()
	}()
	timer := time.NewTimer(wait)
	select {
	case writeErr := <-result:
		stopTimer(timer)
		return writeErr
	case <-timer.C:
		// WebSocket Close performs a graceful close-frame write with the
		// global TCP timeout. Close the deepest raw carrier first so the
		// extrojan link timeout remains the actual upper bound.
		forceCloseCarrier(conn)
		return os.ErrDeadlineExceeded
	}
}

type netConnWrapper interface {
	NetConn() net.Conn
}

// forceCloseCarrier unwraps stream adapters and closes the deepest raw
// connection before closing the outer adapter. The second close preserves
// wrapper callbacks while avoiding graceful-close writes on a blocked carrier.
func forceCloseCarrier(conn net.Conn) {
	if conn == nil {
		return
	}
	var current any = conn
	deepest := conn
	unwrapped := false
	for range 32 {
		switch wrapper := current.(type) {
		case common.WithUpstream:
			upstream := wrapper.Upstream()
			if upstream == nil {
				_ = deepest.Close()
				if unwrapped {
					_ = conn.Close()
				}
				return
			}
			if upstreamConn, loaded := upstream.(net.Conn); loaded {
				deepest = upstreamConn
				unwrapped = true
			}
			current = upstream
		case netConnWrapper:
			upstream := wrapper.NetConn()
			if upstream == nil {
				_ = deepest.Close()
				if unwrapped {
					_ = conn.Close()
				}
				return
			}
			deepest = upstream
			unwrapped = true
			current = upstream
		default:
			_ = deepest.Close()
			if unwrapped {
				_ = conn.Close()
			}
			return
		}
	}
	_ = deepest.Close()
	if unwrapped {
		_ = conn.Close()
	}
}
