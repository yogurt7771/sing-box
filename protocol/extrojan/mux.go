package extrojan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	ext "github.com/sagernet/sing-box/transport/extrojan"
	singmux "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/varbin"
)

func resumableYamuxConfig(config ext.Config) *yamux.Config {
	yamuxConfig := yamux.DefaultConfig()
	// Extrojan carriers already have heartbeats and a precise resume timer.
	// A second keepalive here would incorrectly terminate the logical session
	// while all replaceable carriers are temporarily unavailable.
	yamuxConfig.EnableKeepAlive = false
	yamuxConfig.ConnectionWriteTimeout = config.RecoveryBudget()
	yamuxConfig.StreamOpenTimeout = 0
	yamuxConfig.StreamCloseTimeout = config.RecoveryBudget()
	yamuxConfig.LogOutput = io.Discard
	return yamuxConfig
}

func openResumableMuxStream(logicalSession *ext.Session, session *yamux.Session, destination M.Socksaddr) (net.Conn, error) {
	release, err := logicalSession.RetainStream()
	if err != nil {
		return nil, err
	}
	stream, err := session.OpenStream()
	if err != nil {
		release()
		return nil, err
	}
	framed := newFramedMuxConn(stream)
	framed.onClose = release
	return &resumableMuxClientConn{
		framedMuxConn: framed,
		stream:        stream,
		destination:   destination,
	}, nil
}

type resumableMuxClientConn struct {
	*framedMuxConn
	stream      *yamux.Stream
	destination M.Socksaddr

	requestAccess  sync.Mutex
	requestWritten bool
	responseAccess sync.Mutex
	responseRead   bool
}

func (c *resumableMuxClientConn) NeedHandshake() bool {
	c.requestAccess.Lock()
	defer c.requestAccess.Unlock()
	return !c.requestWritten
}

func (c *resumableMuxClientConn) Read(p []byte) (int, error) {
	if err := c.ensureRequest(); err != nil {
		return 0, err
	}
	c.responseAccess.Lock()
	if !c.responseRead {
		response, err := singmux.ReadStreamResponse(c.stream)
		if err != nil {
			c.responseAccess.Unlock()
			return 0, err
		}
		if response.Status != 0 {
			c.responseAccess.Unlock()
			return 0, fmt.Errorf("remote error: %s", response.Message)
		}
		c.responseRead = true
	}
	c.responseAccess.Unlock()
	return c.framedMuxConn.Read(p)
}

func (c *resumableMuxClientConn) Write(p []byte) (int, error) {
	if err := c.ensureRequest(); err != nil {
		return 0, err
	}
	return c.framedMuxConn.Write(p)
}

func (c *resumableMuxClientConn) CloseWrite() error {
	if err := c.ensureRequest(); err != nil {
		return err
	}
	return c.framedMuxConn.CloseWrite()
}

func (c *resumableMuxClientConn) ensureRequest() error {
	c.requestAccess.Lock()
	defer c.requestAccess.Unlock()
	if c.requestWritten {
		return nil
	}
	request := singmux.StreamRequest{
		Network:     N.NetworkTCP,
		Destination: c.destination,
	}
	requestBuffer := buf.NewSize(2 + M.SocksaddrSerializer.AddrPortLen(c.destination))
	defer requestBuffer.Release()
	if err := singmux.EncodeStreamRequest(request, requestBuffer); err != nil {
		return err
	}
	if err := writeMuxFull(c.stream, requestBuffer.Bytes()); err != nil {
		return err
	}
	c.requestWritten = true
	return nil
}

func (c *resumableMuxClientConn) RemoteAddr() net.Addr {
	return c.destination.TCPAddr()
}

func (c *resumableMuxClientConn) ReaderReplaceable() bool {
	c.responseAccess.Lock()
	defer c.responseAccess.Unlock()
	return c.responseRead
}

func (c *resumableMuxClientConn) WriterReplaceable() bool {
	c.requestAccess.Lock()
	defer c.requestAccess.Unlock()
	return c.requestWritten
}

func (c *resumableMuxClientConn) NeedAdditionalReadDeadline() bool {
	return false
}

func (c *resumableMuxClientConn) AllowUpstreamHalfClose() bool {
	return true
}

func (c *resumableMuxClientConn) Upstream() any {
	return c.framedMuxConn
}

func (h *Inbound) serveResumableMux(ctx context.Context, session *ext.Session, source M.Socksaddr) {
	muxSession, err := yamux.Server(session.Stream(), resumableYamuxConfig(session.Config()))
	if err != nil {
		session.CloseWithError(err)
		return
	}
	defer muxSession.Close()
	for {
		stream, acceptErr := muxSession.AcceptStream()
		if acceptErr != nil {
			if session.Err() == nil {
				session.CloseWithError(acceptErr)
			}
			return
		}
		go h.handleResumableMuxStream(log.ContextWithNewID(ctx), stream, source)
	}
}

func (h *Inbound) handleResumableMuxStream(ctx context.Context, stream *yamux.Stream, source M.Socksaddr) {
	request, err := singmux.ReadStreamRequest(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	conn := newResumableMuxServerConn(stream)
	if request.Network != N.NetworkTCP {
		_ = conn.HandshakeFailure(errors.New("extrojan mux only carries TCP streams"))
		_ = conn.Close()
		return
	}
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = request.Destination
	h.newConnection(ctx, conn, metadata, nil)
}

type resumableMuxServerConn struct {
	N.ExtendedConn
	stream *yamux.Stream
	framed *framedMuxConn

	responseAccess  sync.Mutex
	responseWritten bool
}

func newResumableMuxServerConn(stream *yamux.Stream) *resumableMuxServerConn {
	framed := newFramedMuxConn(stream)
	return &resumableMuxServerConn{
		ExtendedConn: bufio.NewExtendedConn(framed),
		stream:       stream,
		framed:       framed,
	}
}

func (c *resumableMuxServerConn) NeedHandshake() bool {
	c.responseAccess.Lock()
	defer c.responseAccess.Unlock()
	return !c.responseWritten
}

func (c *resumableMuxServerConn) HandshakeFailure(handshakeErr error) error {
	message := handshakeErr.Error()
	buffer := buf.NewSize(1 + varbin.UvarintLen(uint64(len(message))) + len(message))
	defer buffer.Release()
	if err := buffer.WriteByte(1); err != nil {
		return err
	}
	if err := varbin.Write(buffer, binary.BigEndian, message); err != nil {
		return err
	}
	return c.writeResponse(buffer.Bytes())
}

func (c *resumableMuxServerConn) HandshakeSuccess() error {
	return c.writeResponse([]byte{0})
}

func (c *resumableMuxServerConn) Write(p []byte) (int, error) {
	c.responseAccess.Lock()
	if !c.responseWritten {
		err := writeMuxFull(c.stream, []byte{0})
		if err == nil {
			c.responseWritten = true
		}
		c.responseAccess.Unlock()
		if err != nil {
			return 0, err
		}
		return c.ExtendedConn.Write(p)
	}
	c.responseAccess.Unlock()
	return c.ExtendedConn.Write(p)
}

func (c *resumableMuxServerConn) WriteBuffer(buffer *buf.Buffer) error {
	c.responseAccess.Lock()
	if !c.responseWritten {
		err := writeMuxFull(c.stream, []byte{0})
		if err == nil {
			c.responseWritten = true
		}
		c.responseAccess.Unlock()
		if err != nil {
			buffer.Release()
			return err
		}
		return c.ExtendedConn.WriteBuffer(buffer)
	}
	c.responseAccess.Unlock()
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *resumableMuxServerConn) CloseWrite() error {
	if err := c.HandshakeSuccess(); err != nil {
		return err
	}
	return c.framed.CloseWrite()
}

func (c *resumableMuxServerConn) NeedAdditionalReadDeadline() bool {
	return false
}

func (c *resumableMuxServerConn) AllowUpstreamHalfClose() bool {
	return true
}

func (c *resumableMuxServerConn) Upstream() any {
	return c.framed
}

func (c *resumableMuxServerConn) writeResponse(payload []byte) error {
	c.responseAccess.Lock()
	defer c.responseAccess.Unlock()
	if c.responseWritten {
		return nil
	}
	if err := writeMuxFull(c.stream, payload); err != nil {
		return err
	}
	c.responseWritten = true
	return nil
}

const (
	muxDataFrame byte = iota
	muxFINFrame
	muxMaxDataFrame = 64 * 1024
)

// framedMuxConn keeps application half-close independent from Yamux's stream
// state machine. Both application FIN markers travel in the ordered data
// stream; the Yamux stream is closed only after both markers have arrived.
type framedMuxConn struct {
	stream *yamux.Stream

	readAccess    sync.Mutex
	readRemaining uint32
	remoteClosed  atomic.Bool

	writeAccess sync.Mutex
	localClosed atomic.Bool

	closeOnce sync.Once
	onClose   func()
}

func newFramedMuxConn(stream *yamux.Stream) *framedMuxConn {
	return &framedMuxConn{stream: stream}
}

func (c *framedMuxConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	for {
		if c.readRemaining > 0 {
			readSize := len(p)
			if uint32(readSize) > c.readRemaining {
				readSize = int(c.readRemaining)
			}
			n, err := c.stream.Read(p[:readSize])
			c.readRemaining -= uint32(n)
			if n > 0 && err == io.EOF {
				err = nil
			}
			return n, err
		}
		if c.remoteClosed.Load() {
			return 0, io.EOF
		}
		var header [5]byte
		if _, err := io.ReadFull(c.stream, header[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint32(header[1:])
		switch header[0] {
		case muxDataFrame:
			if length == 0 || length > muxMaxDataFrame {
				return 0, fmt.Errorf("invalid extrojan mux data length %d", length)
			}
			c.readRemaining = length
		case muxFINFrame:
			if length != 0 {
				return 0, errors.New("invalid extrojan mux FIN")
			}
			c.remoteClosed.Store(true)
			c.closeIfFinished()
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("unknown extrojan mux frame %d", header[0])
		}
	}
}

func (c *framedMuxConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if c.localClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for written < len(p) {
		chunkSize := len(p) - written
		if chunkSize > muxMaxDataFrame {
			chunkSize = muxMaxDataFrame
		}
		var header [5]byte
		header[0] = muxDataFrame
		binary.BigEndian.PutUint32(header[1:], uint32(chunkSize))
		if err := writeMuxFull(c.stream, header[:]); err != nil {
			return written, err
		}
		if err := writeMuxFull(c.stream, p[written:written+chunkSize]); err != nil {
			return written, err
		}
		written += chunkSize
	}
	return written, nil
}

func (c *framedMuxConn) CloseWrite() error {
	c.writeAccess.Lock()
	if c.localClosed.Load() {
		c.writeAccess.Unlock()
		return nil
	}
	var header [5]byte
	header[0] = muxFINFrame
	err := writeMuxFull(c.stream, header[:])
	if err == nil {
		c.localClosed.Store(true)
	}
	c.writeAccess.Unlock()
	if err == nil {
		c.closeIfFinished()
	}
	return err
}

func (c *framedMuxConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		closeErr = c.stream.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return closeErr
}

func (c *framedMuxConn) LocalAddr() net.Addr {
	return c.stream.LocalAddr()
}

func (c *framedMuxConn) RemoteAddr() net.Addr {
	return c.stream.RemoteAddr()
}

func (c *framedMuxConn) SetDeadline(deadline time.Time) error {
	return c.stream.SetDeadline(deadline)
}

func (c *framedMuxConn) SetReadDeadline(deadline time.Time) error {
	return c.stream.SetReadDeadline(deadline)
}

func (c *framedMuxConn) SetWriteDeadline(deadline time.Time) error {
	return c.stream.SetWriteDeadline(deadline)
}

func (c *framedMuxConn) Upstream() any {
	return c.stream
}

func (c *framedMuxConn) closeIfFinished() {
	if c.localClosed.Load() && c.remoteClosed.Load() {
		_ = c.Close()
	}
}

func writeMuxFull(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		n, err := writer.Write(content)
		if n > 0 {
			content = content[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
