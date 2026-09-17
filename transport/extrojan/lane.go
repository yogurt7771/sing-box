package extrojan

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var ErrLinkTimeout = errors.New("extrojan carrier link timeout")

type lane struct {
	id      uint32
	conn    net.Conn
	session *Session

	sendQueue chan []byte
	done      chan struct{}
	closeOnce sync.Once
	writeMu   sync.Mutex

	closedFlag atomic.Bool
	queueBytes atomic.Int64
	lastRead   atomic.Int64
	createdAt  time.Time
}

func newLane(id uint32, conn net.Conn, session *Session) *lane {
	item := &lane{
		id:        id,
		conn:      conn,
		session:   session,
		sendQueue: make(chan []byte, session.config.LaneQueueSize),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
	item.lastRead.Store(time.Now().UnixNano())
	return item
}

func (l *lane) start() {
	go l.readLoop()
	go l.writeLoop()
	go l.heartbeatLoop()
}

func (l *lane) enqueue(frame []byte) bool {
	if l.closedFlag.Load() {
		return false
	}
	l.queueBytes.Add(int64(len(frame)))
	select {
	case <-l.done:
		l.queueBytes.Add(-int64(len(frame)))
		return false
	case l.sendQueue <- frame:
		return true
	default:
		l.queueBytes.Add(-int64(len(frame)))
		return false
	}
}

func (l *lane) readLoop() {
	for {
		frameType, payload, err := ReadFrame(l.conn, l.session.config.MaxFrameSize)
		if err != nil {
			l.closeWithError(err)
			return
		}
		l.lastRead.Store(time.Now().UnixNano())
		if err = l.session.handleFrame(l, frameType, payload); err != nil {
			l.closeWithError(err)
			return
		}
	}
}

func (l *lane) writeLoop() {
	for {
		select {
		case <-l.done:
			return
		case frame := <-l.sendQueue:
			l.queueBytes.Add(-int64(len(frame)))
			if err := l.write(frame); err != nil {
				l.closeWithError(err)
				return
			}
		}
	}
}

func (l *lane) write(frame []byte) error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	select {
	case <-l.done:
		return net.ErrClosed
	default:
	}
	return writeWithDeadline(l.conn, time.Now().Add(l.session.config.LinkTimeout), func() error {
		return writeFull(l.conn, frame)
	})
}

func (l *lane) heartbeatLoop() {
	ticker := time.NewTicker(l.session.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.done:
			return
		case now := <-ticker.C:
			lastRead := time.Unix(0, l.lastRead.Load())
			if now.Sub(lastRead) >= l.session.config.LinkTimeout {
				l.closeWithError(ErrLinkTimeout)
				return
			}
			var nonce [8]byte
			binary.BigEndian.PutUint64(nonce[:], uint64(now.UnixNano()))
			frame, err := EncodeFrame(FramePing, nonce[:], l.session.config.MaxFrameSize)
			if err != nil {
				l.closeWithError(err)
				return
			}
			// Data already queued also provides liveness pressure. Do not evict
			// it merely to make room for a heartbeat.
			_ = l.enqueue(frame)
		}
	}
}

func (l *lane) close() {
	l.closeWithError(net.ErrClosed)
}

func (l *lane) closeWithError(_ error) {
	l.closeOnce.Do(func() {
		l.closedFlag.Store(true)
		close(l.done)
		forceCloseCarrier(l.conn)
		l.session.removeLane(l)
	})
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if written > 0 {
			data = data[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
