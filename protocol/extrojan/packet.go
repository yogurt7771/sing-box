package extrojan

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// resumablePacketConn keeps the application-facing UDP association alive when
// an idle timeout or session failure retires the underlying extrojan
// association. Reads wait without a current association; the next application
// write opens a fresh session/association.
type resumablePacketConn struct {
	outbound    *Outbound
	ctx         context.Context
	cancel      context.CancelFunc
	destination M.Socksaddr
	localAddr   net.Addr

	access        sync.Mutex
	current       net.PacketConn
	opening       bool
	closed        bool
	wake          chan struct{}
	readDeadline  time.Time
	writeDeadline time.Time
}

func newResumablePacketConn(ctx context.Context, outbound *Outbound, destination M.Socksaddr, current net.PacketConn) *resumablePacketConn {
	if ctx == nil {
		ctx = context.Background()
	}
	lifecycleContext, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &resumablePacketConn{
		outbound:    outbound,
		ctx:         lifecycleContext,
		cancel:      cancel,
		destination: destination,
		localAddr:   current.LocalAddr(),
		current:     current,
		wake:        make(chan struct{}),
	}
}

func (c *resumablePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	startLength := buffer.Len()
	for {
		current, err := c.waitCurrent(true)
		if err != nil {
			return M.Socksaddr{}, err
		}
		if packetReader, loaded := current.(N.PacketReader); loaded {
			destination, readErr := packetReader.ReadPacket(buffer)
			if readErr == nil {
				return destination, nil
			}
			if isPacketTimeout(readErr) || errors.Is(readErr, io.ErrShortBuffer) {
				return M.Socksaddr{}, readErr
			}
			buffer.Truncate(startLength)
			c.invalidate(current)
			continue
		}
		n, destination, readErr := current.ReadFrom(buffer.FreeBytes())
		if n > 0 {
			buffer.Truncate(startLength + n)
		}
		if readErr == nil {
			return M.SocksaddrFromNet(destination), nil
		}
		if isPacketTimeout(readErr) {
			return M.Socksaddr{}, readErr
		}
		buffer.Truncate(startLength)
		c.invalidate(current)
	}
}

func (c *resumablePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	var address net.Addr = destination
	if !destination.IsDomain() {
		address = destination.UDPAddr()
	}
	_, err := c.WriteTo(buffer.Bytes(), address)
	return err
}

func (c *resumablePacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	for {
		current, err := c.waitCurrent(true)
		if err != nil {
			return 0, nil, err
		}
		n, destination, readErr := current.ReadFrom(payload)
		if readErr == nil {
			return n, destination, nil
		}
		if isPacketTimeout(readErr) {
			return n, destination, readErr
		}
		c.invalidate(current)
	}
}

func (c *resumablePacketConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		current, err := c.ensureCurrent()
		if err != nil {
			return 0, err
		}
		n, writeErr := current.WriteTo(payload, destination)
		if writeErr == nil {
			return n, nil
		}
		if isPacketTimeout(writeErr) {
			return n, writeErr
		}
		if n > 0 {
			return n, writeErr
		}
		lastErr = writeErr
		c.invalidate(current)
	}
	return 0, lastErr
}

func (c *resumablePacketConn) Close() error {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	c.closed = true
	current := c.current
	c.current = nil
	c.notifyLocked()
	c.access.Unlock()
	c.cancel()
	if c.outbound != nil {
		c.outbound.removePacketConn(c)
	}
	if current != nil {
		return current.Close()
	}
	return nil
}

func (c *resumablePacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *resumablePacketConn) SetDeadline(deadline time.Time) error {
	c.access.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	current := c.current
	c.notifyLocked()
	c.access.Unlock()
	if current != nil {
		return current.SetDeadline(deadline)
	}
	return nil
}

func (c *resumablePacketConn) SetReadDeadline(deadline time.Time) error {
	c.access.Lock()
	c.readDeadline = deadline
	current := c.current
	c.notifyLocked()
	c.access.Unlock()
	if current != nil {
		return current.SetReadDeadline(deadline)
	}
	return nil
}

func (c *resumablePacketConn) SetWriteDeadline(deadline time.Time) error {
	c.access.Lock()
	c.writeDeadline = deadline
	current := c.current
	c.notifyLocked()
	c.access.Unlock()
	if current != nil {
		return current.SetWriteDeadline(deadline)
	}
	return nil
}

func (c *resumablePacketConn) ensureCurrent() (net.PacketConn, error) {
	for {
		c.access.Lock()
		if c.closed {
			c.access.Unlock()
			return nil, net.ErrClosed
		}
		if c.current != nil {
			current := c.current
			c.access.Unlock()
			return current, nil
		}
		if c.opening {
			wake := c.wake
			deadline := c.writeDeadline
			c.access.Unlock()
			if err := waitPacketWake(wake, deadline); err != nil {
				return nil, err
			}
			continue
		}
		c.opening = true
		deadline := c.writeDeadline
		c.access.Unlock()

		openDeadline := time.Now().Add(c.outbound.config.LinkTimeout)
		if !deadline.IsZero() && deadline.Before(openDeadline) {
			openDeadline = deadline
		}
		if !time.Now().Before(openDeadline) {
			_, _ = c.finishOpen(nil)
			return nil, os.ErrDeadlineExceeded
		}
		openContext, cancel := context.WithDeadline(c.ctx, openDeadline)
		packetConn, err := c.outbound.openExtrojanPacket(openContext, c.destination)
		cancel()
		if err != nil {
			_, _ = c.finishOpen(nil)
			return nil, err
		}
		installed, installErr := c.finishOpen(packetConn)
		if installErr != nil {
			_ = packetConn.Close()
			return nil, installErr
		}
		if !installed {
			_ = packetConn.Close()
			return nil, net.ErrClosed
		}
		return packetConn, nil
	}
}

func (c *resumablePacketConn) waitCurrent(read bool) (net.PacketConn, error) {
	for {
		c.access.Lock()
		if c.closed {
			c.access.Unlock()
			return nil, net.ErrClosed
		}
		if c.current != nil {
			current := c.current
			c.access.Unlock()
			return current, nil
		}
		wake := c.wake
		deadline := c.writeDeadline
		if read {
			deadline = c.readDeadline
		}
		c.access.Unlock()
		if err := waitPacketWake(wake, deadline); err != nil {
			return nil, err
		}
	}
}

func (c *resumablePacketConn) finishOpen(packetConn net.PacketConn) (bool, error) {
	c.access.Lock()
	c.opening = false
	installed := !c.closed && c.current == nil && packetConn != nil
	if installed {
		if err := applyPacketDeadlines(packetConn, c.readDeadline, c.writeDeadline); err != nil {
			c.notifyLocked()
			c.access.Unlock()
			return false, err
		}
		c.current = packetConn
	}
	c.notifyLocked()
	c.access.Unlock()
	return installed, nil
}

func (c *resumablePacketConn) invalidate(target net.PacketConn) {
	c.access.Lock()
	if c.current == target {
		c.current = nil
		c.notifyLocked()
	}
	c.access.Unlock()
	_ = target.Close()
}

func applyPacketDeadlines(packetConn net.PacketConn, readDeadline time.Time, writeDeadline time.Time) error {
	if readDeadline == writeDeadline {
		return packetConn.SetDeadline(readDeadline)
	}
	if err := packetConn.SetReadDeadline(readDeadline); err != nil {
		return err
	}
	return packetConn.SetWriteDeadline(writeDeadline)
}

func (c *resumablePacketConn) notifyLocked() {
	close(c.wake)
	c.wake = make(chan struct{})
}

func waitPacketWake(wake <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		<-wake
		return nil
	}
	wait := time.Until(deadline)
	if wait <= 0 {
		return os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(wait)
	select {
	case <-wake:
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		return nil
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

func isPacketTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}
