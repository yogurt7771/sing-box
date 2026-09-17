package extrojan

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/transport/trojan"
)

var ErrLegacyServer = errors.New("server does not support extrojan")

type joinRejectedError struct {
	status  byte
	message string
}

func (e *joinRejectedError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("extrojan join rejected with status %d", e.status)
	}
	return fmt.Sprintf("extrojan join rejected: %s", e.message)
}

func isTerminalJoinRejection(err error) bool {
	var rejection *joinRejectedError
	if !errors.As(err, &rejection) {
		return false
	}
	switch rejection.status {
	case StatusUnsupportedVersion, StatusUnauthorized, StatusNotFound, StatusInvalidRequest:
		return true
	default:
		return false
	}
}

type DialFunc func(context.Context) (net.Conn, error)

type Client struct {
	config Config
	key    [trojan.KeyLength]byte
	dial   DialFunc

	access   sync.Mutex
	sessions map[*Session]struct{}
	closed   bool
}

func NewClient(config Config, key [trojan.KeyLength]byte, dial DialFunc) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if dial == nil {
		return nil, errors.New("missing extrojan dial function")
	}
	return &Client{
		config:   config,
		key:      key,
		dial:     dial,
		sessions: make(map[*Session]struct{}),
	}, nil
}

func (c *Client) Close() error {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	c.closed = true
	sessions := make([]*Session, 0, len(c.sessions))
	for session := range c.sessions {
		sessions = append(sessions, session)
	}
	c.access.Unlock()
	for _, session := range sessions {
		session.CloseWithError(net.ErrClosed)
	}
	return nil
}

func (c *Client) DropLanes() {
	c.access.Lock()
	sessions := make([]*Session, 0, len(c.sessions))
	for session := range c.sessions {
		sessions = append(sessions, session)
	}
	c.access.Unlock()
	for _, session := range sessions {
		session.DropLanes()
	}
}

// OpenSession creates the generic logical session used by the sing-mux
// integration. It may carry both muxed TCP streams and UDP associations.
func (c *Client) OpenSession(ctx context.Context) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil, net.ErrClosed
	}
	c.access.Unlock()

	handshakeDeadline := time.Now().Add(c.config.LegacyProbeTimeout)
	if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(handshakeDeadline) {
		handshakeDeadline = contextDeadline
	}
	handshakeContext, cancelHandshake := context.WithDeadline(ctx, handshakeDeadline)
	defer cancelHandshake()
	conn, err := c.dial(handshakeContext)
	if err != nil {
		return nil, err
	}
	conn = PrepareHandshakeConn(conn)
	if err = setHandshakeDeadline(conn, handshakeDeadline); err != nil {
		forceCloseCarrier(conn)
		return nil, err
	}
	err = writeWithDeadline(conn, handshakeDeadline, func() error {
		return WriteOpenRequest(conn, c.key, OpenRequest{
			Version:        ProtocolVersion,
			RequestedLanes: uint16(c.config.Connections),
		})
	})
	if err != nil {
		forceCloseCarrier(conn)
		if !isTimeout(err) && ctx.Err() == nil {
			// A legacy Trojan server may reset the connection as soon as it
			// sees the extension command, while the remaining OPEN fields are
			// still being written.
			return nil, fmt.Errorf("%w: %v", ErrLegacyServer, err)
		}
		return nil, err
	}
	response, err := ReadOpenResponse(conn)
	if err != nil {
		forceCloseCarrier(conn)
		if isTimeout(err) || ctx.Err() != nil {
			return nil, err
		}
		// A legacy Trojan server normally closes after seeing the extension
		// command, or sends bytes that do not carry the extrojan magic.
		return nil, fmt.Errorf("%w: %v", ErrLegacyServer, err)
	}
	if response.Status != StatusOK {
		forceCloseCarrier(conn)
		if response.Status == StatusUnsupportedVersion {
			return nil, fmt.Errorf("%w: %s", ErrLegacyServer, response.Message)
		}
		return nil, fmt.Errorf("extrojan open rejected: %s", response.Message)
	}
	if response.Version != ProtocolVersion {
		forceCloseCarrier(conn)
		return nil, fmt.Errorf("%w: server selected version %d", ErrLegacyServer, response.Version)
	}
	if response.AcceptedLanes == 0 || int(response.AcceptedLanes) > c.config.Connections {
		forceCloseCarrier(conn)
		return nil, errors.New("server selected an invalid extrojan lane count")
	}
	if err = setHandshakeDeadline(conn, time.Time{}); err != nil {
		forceCloseCarrier(conn)
		return nil, err
	}

	sessionConfig := c.config
	if response.ResumeTimeoutMS > 0 {
		sessionConfig.ResumeTimeout = time.Duration(response.ResumeTimeoutMS) * time.Millisecond
	}
	sessionConfig.Connections = int(response.AcceptedLanes)
	session, err := NewSession(SessionOptions{
		Context:     context.Background(),
		Config:      sessionConfig,
		ID:          response.SessionID,
		ResumeToken: response.ResumeToken,
		Server:      false,
		LocalAddr:   conn.LocalAddr(),
		RemoteAddr:  conn.RemoteAddr(),
		OnClose:     c.removeSession,
	})
	if err != nil {
		forceCloseCarrier(conn)
		return nil, err
	}
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		session.CloseWithError(net.ErrClosed)
		forceCloseCarrier(conn)
		return nil, net.ErrClosed
	}
	c.sessions[session] = struct{}{}
	c.access.Unlock()

	if err = session.AddLane(response.LaneID, conn); err != nil {
		session.CloseWithError(err)
		return nil, err
	}
	go c.maintainLanes(session)
	return session, nil
}

func (c *Client) maintainLanes(session *Session) {
	delay := session.config.ReconnectInitialDelay
	var rotationTimer *time.Timer
	var rotationWake <-chan time.Time
	if session.config.LaneRotationInterval > 0 {
		rotationTimer = time.NewTimer(session.config.LaneRotationInterval)
		rotationWake = rotationTimer.C
		defer stopTimer(rotationTimer)
	}
	resetRotation := func() {
		if rotationTimer == nil {
			return
		}
		stopTimer(rotationTimer)
		rotationTimer.Reset(session.config.LaneRotationInterval)
	}
	for {
		select {
		case <-session.Done():
			return
		default:
		}
		if session.LaneCount() >= session.config.Connections {
			select {
			case <-session.LaneChanges():
			case <-rotationWake:
				if session.HasActiveUDPAssociations() {
					session.rotateOldestLane()
				}
				resetRotation()
			case <-session.Done():
				return
			}
			continue
		}
		if wait := session.rotationReconnectDelay(); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-session.Done():
				stopTimer(timer)
				return
			}
		}
		err := c.joinLane(session)
		if err == nil {
			delay = session.config.ReconnectInitialDelay
			resetRotation()
			continue
		}
		// A permanent rejection is authoritative only after every existing
		// carrier has disappeared. If one lane is still alive, the rejected
		// JOIN may have reached a different, non-sticky backend during a
		// rolling restart.
		if session.LaneCount() == 0 && isTerminalJoinRejection(err) {
			session.CloseWithError(err)
			return
		}
		timer := time.NewTimer(jitter(delay))
		select {
		case <-timer.C:
		case <-session.LaneChanges():
			stopTimer(timer)
		case <-session.Done():
			stopTimer(timer)
			return
		}
		delay *= 2
		if delay > session.config.ReconnectMaxDelay {
			delay = session.config.ReconnectMaxDelay
		}
	}
}

func (c *Client) joinLane(session *Session) error {
	ctx, cancel := context.WithTimeout(session.Context(), session.config.LinkTimeout)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	conn = PrepareHandshakeConn(conn)
	defer func() {
		if conn != nil {
			forceCloseCarrier(conn)
		}
	}()
	handshakeDeadline := time.Now().Add(session.config.LinkTimeout)
	if err = setHandshakeDeadline(conn, handshakeDeadline); err != nil {
		return err
	}
	err = writeWithDeadline(conn, handshakeDeadline, func() error {
		return WriteJoinRequest(conn, c.key, JoinRequest{
			Version:     ProtocolVersion,
			SessionID:   session.ID(),
			ResumeToken: session.ResumeToken(),
		})
	})
	if err != nil {
		return err
	}
	response, err := ReadJoinResponse(conn)
	if err != nil {
		return err
	}
	if response.Status != StatusOK {
		return &joinRejectedError{
			status:  response.Status,
			message: response.Message,
		}
	}
	if response.Version != ProtocolVersion {
		return fmt.Errorf("extrojan join selected unsupported version %d", response.Version)
	}
	if err = setHandshakeDeadline(conn, time.Time{}); err != nil {
		return err
	}
	if err = session.AddLane(response.LaneID, conn); err != nil {
		return err
	}
	conn = nil
	return nil
}

func (c *Client) removeSession(session *Session) {
	c.access.Lock()
	delete(c.sessions, session)
	c.access.Unlock()
}

func jitter(delay time.Duration) time.Duration {
	quarter := delay / 4
	if quarter <= 0 {
		return delay
	}
	return delay - quarter + time.Duration(rand.Int64N(int64(quarter*2)+1))
}

func isTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}
