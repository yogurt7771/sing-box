package extrojan

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

var ErrUDPIdleTimeout = errors.New("extrojan UDP idle timeout")

type packet struct {
	data        []byte
	destination M.Socksaddr
}

// PacketConn is one logical UDP association. Frames may use any healthy TCP
// lane, but datagrams are never replayed after a carrier failure.
type PacketConn struct {
	session       *Session
	associationID uint64
	destination   M.Socksaddr

	receive    chan packet
	openResult chan byte
	closed     chan struct{}
	closeOnce  sync.Once

	access        sync.Mutex
	closedFlag    bool
	closeErr      error
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineWake  chan struct{}
	lastActivity  time.Time
	idleTimer     *time.Timer
	idleStarted   bool
	idleExpiring  bool
}

func newPacketConn(session *Session, associationID uint64, destination M.Socksaddr) *PacketConn {
	return &PacketConn{
		session:       session,
		associationID: associationID,
		destination:   destination,
		receive:       make(chan packet, session.config.UDPQueueSize),
		openResult:    make(chan byte, 1),
		closed:        make(chan struct{}),
		deadlineWake:  make(chan struct{}, 1),
	}
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	item, err := c.readPacket()
	if err != nil {
		return M.Socksaddr{}, err
	}
	if len(item.data) > buffer.FreeLen() {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	n, err := buffer.Write(item.data)
	if err != nil {
		return M.Socksaddr{}, err
	}
	if n != len(item.data) {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	return item.destination, nil
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	return c.writePacket(buffer.Bytes(), destination)
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	item, err := c.readPacket()
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, item.data)
	if item.destination.IsDomain() {
		return n, item.destination, nil
	}
	return n, item.destination.UDPAddr(), nil
}

func (c *PacketConn) WriteTo(p []byte, address net.Addr) (int, error) {
	if err := c.writePacket(p, M.SocksaddrFromNet(address)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *PacketConn) Close() error {
	c.close(true, net.ErrClosed)
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	return c.session.localAddr
}

func (c *PacketConn) SetDeadline(deadline time.Time) error {
	c.access.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.access.Unlock()
	c.notifyDeadline()
	return nil
}

func (c *PacketConn) SetReadDeadline(deadline time.Time) error {
	c.access.Lock()
	c.readDeadline = deadline
	c.access.Unlock()
	c.notifyDeadline()
	return nil
}

func (c *PacketConn) SetWriteDeadline(deadline time.Time) error {
	c.access.Lock()
	c.writeDeadline = deadline
	c.access.Unlock()
	c.notifyDeadline()
	return nil
}

func (c *PacketConn) readPacket() (packet, error) {
	for {
		c.access.Lock()
		deadline := c.readDeadline
		c.access.Unlock()
		if deadline.IsZero() {
			select {
			case item := <-c.receive:
				c.session.releaseUDPBytes(len(item.data))
				return item, nil
			case <-c.deadlineWake:
				continue
			case <-c.closed:
				return packet{}, c.err()
			case <-c.session.closed:
				return packet{}, c.session.Err()
			}
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return packet{}, timeoutError{}
		}
		timer := time.NewTimer(wait)
		select {
		case item := <-c.receive:
			stopTimer(timer)
			c.session.releaseUDPBytes(len(item.data))
			return item, nil
		case <-c.deadlineWake:
			stopTimer(timer)
		case <-c.closed:
			stopTimer(timer)
			return packet{}, c.err()
		case <-c.session.closed:
			stopTimer(timer)
			return packet{}, c.session.Err()
		case <-timer.C:
			return packet{}, timeoutError{}
		}
	}
}

func (c *PacketConn) writePacket(data []byte, destination M.Socksaddr) error {
	select {
	case <-c.closed:
		return c.err()
	case <-c.session.closed:
		return c.session.Err()
	default:
	}
	if len(data) > DefaultMaxUDPPayload {
		return errors.New("extrojan UDP payload too large")
	}
	c.access.Lock()
	deadline := c.writeDeadline
	c.access.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return timeoutError{}
	}
	if !c.touchActivity() {
		return c.err()
	}
	payload, err := EncodeUDPData(c.associationID, destination, data)
	if err != nil {
		return err
	}
	// sendFrame is deliberately non-blocking. A false result means every
	// lane is unavailable or saturated, so this datagram is dropped.
	_ = c.session.sendFrame(FrameUDPData, payload)
	return nil
}

func (c *PacketConn) reportOpen(status byte) {
	select {
	case <-c.closed:
		return
	default:
	}
	select {
	case c.openResult <- status:
	default:
	}
}

func (c *PacketConn) deliver(destination M.Socksaddr, data []byte) {
	c.access.Lock()
	if c.closedFlag || c.idleExpiring {
		c.access.Unlock()
		return
	}
	if c.idleStarted {
		c.lastActivity = time.Now()
	}
	if !c.session.reserveUDPBytes(len(data)) {
		c.access.Unlock()
		return
	}
	item := packet{
		data:        append([]byte(nil), data...),
		destination: destination,
	}
	select {
	case c.receive <- item:
	default:
		c.session.releaseUDPBytes(len(item.data))
		// UDP is lossy by definition; keeping this queue bounded prevents a
		// slow consumer from exhausting a resumable session.
	}
	c.access.Unlock()
}

func (c *PacketConn) closeRemote() {
	c.close(false, io.EOF)
}

func (c *PacketConn) close(sendClose bool, err error) {
	c.closeOnce.Do(func() {
		c.access.Lock()
		c.closedFlag = true
		c.closeErr = err
		if c.idleTimer != nil {
			c.idleTimer.Stop()
			c.idleTimer = nil
		}
		for {
			select {
			case item := <-c.receive:
				c.session.releaseUDPBytes(len(item.data))
			default:
				c.access.Unlock()
				close(c.closed)
				c.notifyDeadline()
				c.session.closePacket(c.associationID, c, sendClose)
				return
			}
		}
	})
}

func (c *PacketConn) startIdleTimer() {
	timeout := c.session.config.UDPIdleTimeout
	if timeout <= 0 {
		return
	}
	c.access.Lock()
	if c.closedFlag || c.idleExpiring || c.idleStarted {
		c.access.Unlock()
		return
	}
	c.idleStarted = true
	c.lastActivity = time.Now()
	c.idleTimer = time.AfterFunc(timeout, c.expireIdle)
	c.access.Unlock()
}

func (c *PacketConn) touchActivity() bool {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closedFlag || c.idleExpiring {
		return false
	}
	if c.idleStarted {
		c.lastActivity = time.Now()
	}
	return true
}

func (c *PacketConn) expireIdle() {
	timeout := c.session.config.UDPIdleTimeout
	c.access.Lock()
	if c.closedFlag || c.idleExpiring || !c.idleStarted {
		c.access.Unlock()
		return
	}
	idleFor := time.Since(c.lastActivity)
	if idleFor < timeout {
		c.idleTimer.Reset(timeout - idleFor)
		c.access.Unlock()
		return
	}
	c.idleExpiring = true
	c.idleTimer = nil
	c.access.Unlock()
	c.close(true, ErrUDPIdleTimeout)
}

func (c *PacketConn) err() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closeErr != nil {
		return c.closeErr
	}
	return net.ErrClosed
}

func (c *PacketConn) notifyDeadline() {
	select {
	case c.deadlineWake <- struct{}{}:
	default:
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
