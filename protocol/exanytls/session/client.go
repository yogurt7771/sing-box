// Derived from github.com/anytls/sing-anytls/session (GPL-3.0-or-later).
package session

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/skiplist"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

type DialFunc func(context.Context) (net.Conn, error)

type ClientOptions struct {
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
	Session                  Options
	// SessionOptionsFor derives the options for one pooled session from the
	// carrier that was actually dialed. How long a session may block before it
	// gives up depends on whether that carrier can recover, which is only known
	// after the dial, so a single static value cannot be correct for every
	// carrier this client creates.
	SessionOptionsFor func(net.Conn) Options
}

// Client preserves the standard AnyTLS session-pool behavior while allowing
// callers to provide a different transport for each pooled AnyTLS session.
type Client struct {
	die       context.Context
	dieCancel context.CancelFunc

	dialOut           DialFunc
	sessionOptions    Options
	sessionOptionsFor func(net.Conn) Options

	sessionCounter atomic.Uint64

	idleSession     *skiplist.SkipList[uint64, *Session]
	idleSessionLock sync.Mutex

	sessions     map[uint64]*Session
	sessionsLock sync.Mutex

	padding *atomic.TypedValue[*padding.PaddingFactory]
	logger  logger.Logger

	idleSessionTimeout time.Duration
	minIdleSession     int
}

func NewClient(
	ctx context.Context,
	clientLogger logger.Logger,
	dialOut DialFunc,
	paddingFactory *atomic.TypedValue[*padding.PaddingFactory],
	options ClientOptions,
) *Client {
	if ctx == nil {
		ctx = context.Background()
	}
	if options.IdleSessionCheckInterval <= 5*time.Second {
		options.IdleSessionCheckInterval = 30 * time.Second
	}
	if options.IdleSessionTimeout <= 5*time.Second {
		options.IdleSessionTimeout = 30 * time.Second
	}
	clientContext, cancel := context.WithCancel(ctx)
	client := &Client{
		die:                clientContext,
		dieCancel:          cancel,
		dialOut:            dialOut,
		sessionOptions:     options.Session,
		sessionOptionsFor:  options.SessionOptionsFor,
		idleSession:        skiplist.NewSkipList[uint64, *Session](),
		sessions:           make(map[uint64]*Session),
		padding:            paddingFactory,
		logger:             clientLogger,
		idleSessionTimeout: options.IdleSessionTimeout,
		minIdleSession:     options.MinIdleSession,
	}
	go client.runIdleCleanup(options.IdleSessionCheckInterval)
	return client
}

func (c *Client) runIdleCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.idleCleanup()
		case <-c.die.Done():
			return
		}
	}
}

func (c *Client) CreateStream(ctx context.Context) (*Stream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-c.die.Done():
		return nil, io.ErrClosedPipe
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	pooledSession := c.getIdleSession()
	var err error
	if pooledSession == nil {
		pooledSession, err = c.createSession(ctx)
	}
	if pooledSession == nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	stream, err := pooledSession.openStream(func() {
		c.recycleSession(pooledSession)
	})
	if err != nil {
		_ = pooledSession.Close()
		return nil, fmt.Errorf("failed to create stream: %w", err)
	}
	return stream, nil
}

func (c *Client) getIdleSession() *Session {
	for {
		c.idleSessionLock.Lock()
		if c.idleSession.IsEmpty() {
			c.idleSessionLock.Unlock()
			return nil
		}
		iterator := c.idleSession.Iterate()
		pooledSession := iterator.Value()
		c.idleSession.Remove(iterator.Key())
		c.idleSessionLock.Unlock()
		if !pooledSession.IsClosed() {
			return pooledSession
		}
	}
}

func (c *Client) createSession(ctx context.Context) (*Session, error) {
	dialContext, cancel := context.WithCancel(ctx)
	stopCancel := context.AfterFunc(c.die, cancel)
	defer func() {
		stopCancel()
		cancel()
	}()

	underlying, err := c.dialOut(dialContext)
	if err != nil {
		return nil, err
	}
	sessionOptions := c.sessionOptions
	if c.sessionOptionsFor != nil {
		sessionOptions = c.sessionOptionsFor(underlying)
	}
	pooledSession := NewClientSession(underlying, c.padding, c.logger, sessionOptions)
	pooledSession.seq = c.sessionCounter.Add(1)
	pooledSession.dieHook = func() {
		c.idleSessionLock.Lock()
		c.idleSession.Remove(math.MaxUint64 - pooledSession.seq)
		c.idleSessionLock.Unlock()

		c.sessionsLock.Lock()
		delete(c.sessions, pooledSession.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
	select {
	case <-c.die.Done():
		c.sessionsLock.Unlock()
		_ = pooledSession.Close()
		return nil, io.ErrClosedPipe
	default:
		c.sessions[pooledSession.seq] = pooledSession
		c.sessionsLock.Unlock()
	}

	pooledSession.Run()
	return pooledSession, nil
}

func (c *Client) recycleSession(pooledSession *Session) {
	if pooledSession.IsClosed() {
		return
	}
	select {
	case <-c.die.Done():
		go pooledSession.Close()
		return
	default:
	}
	c.idleSessionLock.Lock()
	if !pooledSession.IsClosed() {
		pooledSession.idleSince = time.Now()
		c.idleSession.Insert(math.MaxUint64-pooledSession.seq, pooledSession)
	}
	c.idleSessionLock.Unlock()
}

func (c *Client) Close() error {
	c.dieCancel()
	c.closeSessions()
	return nil
}

// Reset closes every pooled session without closing the client. New streams
// can create fresh sessions, which is used after a network-interface change.
func (c *Client) Reset() {
	c.closeSessions()
}

func (c *Client) closeSessions() {
	c.sessionsLock.Lock()
	sessions := make([]*Session, 0, len(c.sessions))
	for _, pooledSession := range c.sessions {
		sessions = append(sessions, pooledSession)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsLock.Unlock()

	c.idleSessionLock.Lock()
	c.idleSession = skiplist.NewSkipList[uint64, *Session]()
	c.idleSessionLock.Unlock()

	for _, pooledSession := range sessions {
		_ = pooledSession.Close()
	}
}

func (c *Client) idleCleanup() {
	c.idleCleanupExpTime(time.Now().Add(-c.idleSessionTimeout))
}

func (c *Client) idleCleanupExpTime(expiration time.Time) {
	activeCount := 0
	var sessionsToClose []*Session

	c.idleSessionLock.Lock()
	iterator := c.idleSession.Iterate()
	for iterator.IsNotEnd() {
		pooledSession := iterator.Value()
		key := iterator.Key()
		iterator.MoveToNext()

		if !pooledSession.idleSince.Before(expiration) {
			activeCount++
			continue
		}
		if activeCount < c.minIdleSession {
			pooledSession.idleSince = time.Now()
			activeCount++
			continue
		}
		sessionsToClose = append(sessionsToClose, pooledSession)
		c.idleSession.Remove(key)
	}
	c.idleSessionLock.Unlock()

	for _, pooledSession := range sessionsToClose {
		_ = pooledSession.Close()
	}
}
