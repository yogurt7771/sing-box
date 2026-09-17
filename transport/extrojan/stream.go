package extrojan

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type sendSegment struct {
	offset   uint64
	data     []byte
	lastSent time.Time
}

// ReliableConn is the ordered byte stream used by the upper mux layer. It
// retains only bounded, unacknowledged data and can therefore survive carrier
// replacement without exposing a TCP reset to its caller.
type ReliableConn struct {
	session *Session

	access sync.Mutex

	sendNext    uint64
	sendAcked   uint64
	sendPending []*sendSegment
	sendBytes   int
	sendClosed  bool
	sendFINAt   uint64
	sendFINAck  bool
	sendFINLast time.Time

	recvNext     uint64
	recvPending  map[uint64][]byte
	recvReady    [][]byte
	recvOffset   int
	recvBytes    int
	recvSegments int
	recvFIN      bool
	recvFINAt    uint64

	readDeadline  time.Time
	writeDeadline time.Time
	readNotify    chan struct{}
	writeNotify   chan struct{}
}

func newReliableConn(session *Session) *ReliableConn {
	return &ReliableConn{
		session:     session,
		recvPending: make(map[uint64][]byte),
		readNotify:  make(chan struct{}, 1),
		writeNotify: make(chan struct{}, 1),
	}
}

func (c *ReliableConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.access.Lock()
		if len(c.recvReady) > 0 {
			n := 0
			for len(c.recvReady) > 0 && n < len(p) {
				head := c.recvReady[0]
				copied := copy(p[n:], head[c.recvOffset:])
				n += copied
				c.recvOffset += copied
				c.recvBytes -= copied
				if c.recvOffset == len(head) {
					c.recvReady[0] = nil
					c.recvReady = c.recvReady[1:]
					c.recvOffset = 0
					c.recvSegments--
				}
			}
			c.access.Unlock()
			return n, nil
		}
		if c.recvFIN && c.recvNext == c.recvFINAt {
			c.access.Unlock()
			return 0, io.EOF
		}
		deadline := c.readDeadline
		c.access.Unlock()

		if err := c.session.Err(); err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, err
		}
		if err := waitForSignal(c.readNotify, c.session.closed, deadline); err != nil {
			if errors.Is(err, io.ErrClosedPipe) {
				if sessionErr := c.session.Err(); sessionErr != nil {
					return 0, sessionErr
				}
			}
			return 0, err
		}
	}
}

func (c *ReliableConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(p) {
		chunkSize := len(p) - written
		if chunkSize > StreamChunkSize {
			chunkSize = StreamChunkSize
		}
		for {
			c.access.Lock()
			select {
			case <-c.session.closed:
				c.access.Unlock()
				return written, c.session.Err()
			default:
			}
			if c.sendClosed {
				c.access.Unlock()
				return written, io.ErrClosedPipe
			}
			// While every carrier is gone the session cannot drain, so accept
			// only a small amount of new data instead of the full window. The
			// producer is stalled by the blocking write below, which propagates
			// back pressure to the application on the other side.
			limit := c.session.config.MaxUnackedBytes
			if c.session.activeLanes.Load() == 0 {
				if suspended := c.session.suspendedWriteLimit(); suspended < limit {
					limit = suspended
				}
			}
			if c.sendBytes+chunkSize <= limit &&
				len(c.sendPending) < c.session.config.MaxStreamSegments {
				data := append([]byte(nil), p[written:written+chunkSize]...)
				segment := &sendSegment{
					offset: c.sendNext,
					data:   data,
				}
				c.sendNext += uint64(chunkSize)
				c.sendBytes += chunkSize
				c.sendPending = append(c.sendPending, segment)
				c.access.Unlock()
				written += chunkSize
				c.session.signalSend()
				break
			}
			deadline := c.writeDeadline
			c.access.Unlock()

			if err := c.session.Err(); err != nil {
				return written, err
			}
			if err := waitForSignal(c.writeNotify, c.session.closed, deadline); err != nil {
				if errors.Is(err, io.ErrClosedPipe) {
					if sessionErr := c.session.Err(); sessionErr != nil {
						return written, sessionErr
					}
				}
				return written, err
			}
		}
	}
	return written, nil
}

func (c *ReliableConn) Close() error {
	return c.session.Close()
}

func (c *ReliableConn) CloseWrite() error {
	if err := c.session.Err(); err != nil {
		return err
	}
	c.access.Lock()
	if !c.sendClosed {
		c.sendClosed = true
		c.sendFINAt = c.sendNext
	}
	c.access.Unlock()
	c.session.signalSend()
	return nil
}

// SessionConfig reports the negotiated configuration of the session that owns
// this stream. A protocol layered on top uses it to size its own failure
// budgets against the real recovery window, which is only settled once the
// server has answered the handshake.
func (c *ReliableConn) SessionConfig() Config {
	return c.session.config
}

func (c *ReliableConn) LocalAddr() net.Addr {
	return c.session.localAddr
}

func (c *ReliableConn) RemoteAddr() net.Addr {
	return c.session.remoteAddr
}

func (c *ReliableConn) SetDeadline(deadline time.Time) error {
	c.access.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.access.Unlock()
	c.notifyRead()
	c.notifyWrite()
	return nil
}

func (c *ReliableConn) SetReadDeadline(deadline time.Time) error {
	c.access.Lock()
	c.readDeadline = deadline
	c.access.Unlock()
	c.notifyRead()
	return nil
}

func (c *ReliableConn) SetWriteDeadline(deadline time.Time) error {
	c.access.Lock()
	c.writeDeadline = deadline
	c.access.Unlock()
	c.notifyWrite()
	return nil
}

func (c *ReliableConn) receive(offset uint64, data []byte) (uint64, error) {
	if len(data) == 0 || offset > ^uint64(0)-uint64(len(data)) {
		return 0, errors.New("invalid reliable stream segment")
	}
	c.access.Lock()
	defer c.access.Unlock()

	end := offset + uint64(len(data))
	if c.recvFIN && end > c.recvFINAt {
		return 0, errors.New("reliable stream data exceeds FIN offset")
	}
	if end <= c.recvNext {
		return c.recvNext, nil
	}
	if offset < c.recvNext {
		trim := c.recvNext - offset
		offset = c.recvNext
		data = data[trim:]
	}
	if end-c.recvNext > uint64(c.session.config.MaxReceiveBytes) {
		return c.recvNext, nil
	}
	if existing, loaded := c.recvPending[offset]; loaded {
		if !bytes.Equal(existing, data) {
			return 0, errors.New("conflicting reliable stream segment")
		}
		return c.recvNext, nil
	}
	// Once the object-count limit is reached, reject later out-of-order
	// segments before the overlap scan. The missing in-order segment is still
	// allowed below and can evict the furthest pending segment to make
	// forward progress.
	if c.recvSegments >= c.session.config.MaxStreamSegments && offset != c.recvNext {
		return c.recvNext, nil
	}
	for pendingOffset, pendingData := range c.recvPending {
		pendingEnd := pendingOffset + uint64(len(pendingData))
		dataEnd := offset + uint64(len(data))
		if offset < pendingEnd && pendingOffset < dataEnd {
			return 0, errors.New("overlapping reliable stream segment")
		}
	}
	if c.recvBytes+len(data) > c.session.config.MaxReceiveBytes {
		return c.recvNext, nil
	}
	if c.recvSegments >= c.session.config.MaxStreamSegments {
		if offset != c.recvNext || !c.evictLastPendingLocked() {
			return c.recvNext, nil
		}
	}

	owned := append([]byte(nil), data...)
	c.recvBytes += len(owned)
	c.recvSegments++
	if offset == c.recvNext {
		c.recvReady = append(c.recvReady, owned)
		c.recvNext += uint64(len(owned))
		for {
			next, loaded := c.recvPending[c.recvNext]
			if !loaded {
				break
			}
			delete(c.recvPending, c.recvNext)
			c.recvReady = append(c.recvReady, next)
			c.recvNext += uint64(len(next))
		}
		c.notifyReadLocked()
	} else {
		c.recvPending[offset] = owned
	}
	return c.recvNext, nil
}

func (c *ReliableConn) acknowledge(nextOffset uint64) error {
	c.access.Lock()
	defer c.access.Unlock()
	if nextOffset < c.sendAcked {
		return nil
	}
	if nextOffset > c.sendNext {
		return errors.New("reliable stream ACK exceeds sent offset")
	}
	c.sendAcked = nextOffset
	removeCount := 0
	for _, segment := range c.sendPending {
		segmentEnd := segment.offset + uint64(len(segment.data))
		if segmentEnd > nextOffset {
			break
		}
		c.sendBytes -= len(segment.data)
		removeCount++
	}
	if removeCount > 0 {
		copy(c.sendPending, c.sendPending[removeCount:])
		clear(c.sendPending[len(c.sendPending)-removeCount:])
		c.sendPending = c.sendPending[:len(c.sendPending)-removeCount]
		c.notifyWriteLocked()
	}
	return nil
}

func (c *ReliableConn) evictLastPendingLocked() bool {
	var (
		lastOffset uint64
		lastData   []byte
		loaded     bool
	)
	for offset, data := range c.recvPending {
		if !loaded || offset > lastOffset {
			lastOffset = offset
			lastData = data
			loaded = true
		}
	}
	if !loaded {
		return false
	}
	delete(c.recvPending, lastOffset)
	c.recvBytes -= len(lastData)
	c.recvSegments--
	return true
}

func (c *ReliableConn) receiveFIN(offset uint64) (bool, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.recvFIN {
		if c.recvFINAt != offset {
			return false, errors.New("conflicting reliable stream FIN")
		}
		return c.recvNext == offset, nil
	}
	if offset < c.recvNext {
		return false, errors.New("reliable stream FIN precedes received data")
	}
	for pendingOffset, pendingData := range c.recvPending {
		if pendingOffset > ^uint64(0)-uint64(len(pendingData)) ||
			pendingOffset+uint64(len(pendingData)) > offset {
			return false, errors.New("reliable stream data exceeds FIN offset")
		}
	}
	c.recvFIN = true
	c.recvFINAt = offset
	if c.recvNext == offset {
		c.notifyReadLocked()
		return true, nil
	}
	return false, nil
}

func (c *ReliableConn) readyFIN() (uint64, bool) {
	c.access.Lock()
	defer c.access.Unlock()
	return c.recvFINAt, c.recvFIN && c.recvNext == c.recvFINAt
}

func (c *ReliableConn) acknowledgeFIN(offset uint64) error {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.sendClosed || offset != c.sendFINAt {
		return errors.New("unexpected reliable stream FIN ACK")
	}
	c.sendFINAck = true
	return nil
}

func (c *ReliableConn) dueFIN(now time.Time) (uint64, bool) {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.sendClosed || c.sendFINAck {
		return 0, false
	}
	if !c.sendFINLast.IsZero() && now.Sub(c.sendFINLast) < c.session.config.RetransmitInterval {
		return 0, false
	}
	return c.sendFINAt, true
}

func (c *ReliableConn) markFINSent(sentAt time.Time) {
	c.access.Lock()
	c.sendFINLast = sentAt
	c.access.Unlock()
}

func (c *ReliableConn) dueSegments(now time.Time) []*sendSegment {
	c.access.Lock()
	defer c.access.Unlock()
	var due []*sendSegment
	for _, segment := range c.sendPending {
		if segment.lastSent.IsZero() || now.Sub(segment.lastSent) >= c.session.config.RetransmitInterval {
			due = append(due, &sendSegment{
				offset: segment.offset,
				data:   segment.data,
			})
		}
	}
	return due
}

func (c *ReliableConn) markSent(offset uint64, sentAt time.Time) {
	c.access.Lock()
	defer c.access.Unlock()
	for _, segment := range c.sendPending {
		if segment.offset == offset {
			segment.lastSent = sentAt
			return
		}
	}
}

func (c *ReliableConn) resetSent() {
	c.access.Lock()
	for _, segment := range c.sendPending {
		segment.lastSent = time.Time{}
	}
	c.sendFINLast = time.Time{}
	c.access.Unlock()
}

func (c *ReliableConn) notifyRead() {
	select {
	case c.readNotify <- struct{}{}:
	default:
	}
}

func (c *ReliableConn) notifyReadLocked() {
	select {
	case c.readNotify <- struct{}{}:
	default:
	}
}

func (c *ReliableConn) notifyWrite() {
	select {
	case c.writeNotify <- struct{}{}:
	default:
	}
}

func (c *ReliableConn) notifyWriteLocked() {
	select {
	case c.writeNotify <- struct{}{}:
	default:
	}
}

func waitForSignal(notify <-chan struct{}, closed <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-notify:
			return nil
		case <-closed:
			return io.ErrClosedPipe
		}
	}
	duration := time.Until(deadline)
	if duration <= 0 {
		return timeoutError{}
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-notify:
		return nil
	case <-closed:
		return io.ErrClosedPipe
	case <-timer.C:
		return timeoutError{}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
