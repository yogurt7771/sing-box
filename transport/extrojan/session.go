package extrojan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

var ErrResumeTimeout = errors.New("extrojan resume timeout")

type SessionOptions struct {
	Context     context.Context
	Config      Config
	ID          SessionID
	ResumeToken ResumeToken
	Owner       int
	Server      bool
	LocalAddr   net.Addr
	RemoteAddr  net.Addr
	OnUDPOpen   func(context.Context, *PacketConn, M.Socksaddr)
	OnClose     func(*Session)
}

// Session owns one resumable reliable stream, zero or more UDP associations,
// and a replaceable set of TCP carrier lanes.
type Session struct {
	ctx    context.Context
	cancel context.CancelFunc
	config Config

	id          SessionID
	resumeToken ResumeToken
	owner       int
	server      bool
	localAddr   net.Addr
	remoteAddr  net.Addr
	onUDPOpen   func(context.Context, *PacketConn, M.Socksaddr)
	onClose     func(*Session)

	reliable *ReliableConn

	joinAccess    sync.Mutex
	laneAccess    sync.Mutex
	lanes         map[uint32]*lane
	activeLanes   atomic.Int64
	resumeTimer   *time.Timer
	resumeEpoch   uint64
	resumeExpired bool
	laneChange    chan struct{}
	roundRobin    atomic.Uint64
	rotateAfter   atomic.Int64

	packetAccess        sync.Mutex
	packets             map[uint64]*PacketConn
	pendingPacketCloses map[uint64]time.Time
	packetTombstones    map[uint64]time.Time
	activeStreams       int
	udpLifecycle        bool
	idleClosing         bool
	nextAssociation     atomic.Uint64
	udpQueuedBytes      atomic.Int64

	ackAccess sync.Mutex
	ackNext   uint64
	ackDirty  bool
	sendWake  chan struct{}

	errAccess sync.Mutex
	closeErr  error
	closed    chan struct{}
	closeOnce sync.Once
}

func NewSession(options SessionOptions) (*Session, error) {
	if err := options.Config.Validate(); err != nil {
		return nil, err
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	localAddr := options.LocalAddr
	if localAddr == nil {
		localAddr = logicalAddr{network: "extrojan", address: "local"}
	}
	remoteAddr := options.RemoteAddr
	if remoteAddr == nil {
		remoteAddr = logicalAddr{network: "extrojan", address: "remote"}
	}
	session := &Session{
		ctx:                 ctx,
		cancel:              cancel,
		config:              options.Config,
		id:                  options.ID,
		resumeToken:         options.ResumeToken,
		owner:               options.Owner,
		server:              options.Server,
		localAddr:           localAddr,
		remoteAddr:          remoteAddr,
		onUDPOpen:           options.OnUDPOpen,
		onClose:             options.OnClose,
		lanes:               make(map[uint32]*lane),
		laneChange:          make(chan struct{}, 1),
		packets:             make(map[uint64]*PacketConn),
		pendingPacketCloses: make(map[uint64]time.Time),
		packetTombstones:    make(map[uint64]time.Time),
		sendWake:            make(chan struct{}, 1),
		closed:              make(chan struct{}),
	}
	session.reliable = newReliableConn(session)
	go session.sendLoop()
	return session, nil
}

func (s *Session) ID() SessionID {
	return s.id
}

func (s *Session) ResumeToken() ResumeToken {
	return s.resumeToken
}

func (s *Session) Owner() int {
	return s.owner
}

func (s *Session) Stream() net.Conn {
	return s.reliable
}

func (s *Session) Done() <-chan struct{} {
	return s.closed
}

func (s *Session) Context() context.Context {
	return s.ctx
}

func (s *Session) Config() Config {
	return s.config
}

func (s *Session) LaneChanges() <-chan struct{} {
	return s.laneChange
}

func (s *Session) LaneCount() int {
	s.laneAccess.Lock()
	defer s.laneAccess.Unlock()
	return len(s.lanes)
}

// RetainStream prevents UDP idle cleanup from closing a session while one of
// its muxed TCP streams is still alive.
func (s *Session) RetainStream() (func(), error) {
	s.packetAccess.Lock()
	select {
	case <-s.closed:
		s.packetAccess.Unlock()
		return nil, s.Err()
	default:
	}
	if s.idleClosing {
		s.packetAccess.Unlock()
		return nil, net.ErrClosed
	}
	s.activeStreams++
	s.packetAccess.Unlock()

	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			s.packetAccess.Lock()
			if s.activeStreams > 0 {
				s.activeStreams--
			}
			closeIdle := s.shouldCloseIdleLocked()
			s.packetAccess.Unlock()
			if closeIdle {
				go s.Close()
			}
		})
	}, nil
}

func (s *Session) HasActiveUDPAssociations() bool {
	s.packetAccess.Lock()
	active := len(s.packets) > 0
	s.packetAccess.Unlock()
	return active
}

// AddLane transfers ownership of conn to the session on success.
func (s *Session) AddLane(id uint32, conn net.Conn) error {
	if conn == nil {
		return errors.New("nil extrojan lane")
	}
	select {
	case <-s.closed:
		forceCloseCarrier(conn)
		return s.Err()
	default:
	}
	newLane := newLane(id, conn, s)
	s.laneAccess.Lock()
	select {
	case <-s.closed:
		s.laneAccess.Unlock()
		forceCloseCarrier(conn)
		return s.Err()
	default:
	}
	if s.resumeExpired {
		s.laneAccess.Unlock()
		forceCloseCarrier(conn)
		return ErrResumeTimeout
	}
	if _, loaded := s.lanes[id]; loaded {
		s.laneAccess.Unlock()
		forceCloseCarrier(conn)
		return fmt.Errorf("duplicate extrojan lane %d", id)
	}
	if len(s.lanes) >= s.config.Connections {
		s.laneAccess.Unlock()
		forceCloseCarrier(conn)
		return errors.New("too many extrojan lanes")
	}
	s.resumeEpoch++
	if s.resumeTimer != nil {
		s.resumeTimer.Stop()
		s.resumeTimer = nil
	}
	s.lanes[id] = newLane
	s.activeLanes.Store(int64(len(s.lanes)))
	s.laneAccess.Unlock()

	newLane.start()
	s.reliable.resetSent()
	// A carrier is available again, so writers parked on the suspended write
	// ceiling have to re-evaluate their limit instead of waiting for an ACK.
	s.reliable.notifyWrite()
	s.signalSend()
	s.notifyLaneChange()
	return nil
}

func (s *Session) DropLanes() {
	s.laneAccess.Lock()
	lanes := make([]*lane, 0, len(s.lanes))
	for _, item := range s.lanes {
		lanes = append(lanes, item)
	}
	s.laneAccess.Unlock()
	for _, item := range lanes {
		item.close()
	}
}

// rotateOldestLane removes at most one carrier from a full pool. The client
// lane maintainer observes the removal and establishes its replacement.
func (s *Session) rotateOldestLane() bool {
	s.laneAccess.Lock()
	if len(s.lanes) < s.config.Connections {
		s.laneAccess.Unlock()
		return false
	}
	var oldest *lane
	for _, item := range s.lanes {
		if item.closedFlag.Load() {
			continue
		}
		if oldest == nil || item.createdAt.Before(oldest.createdAt) {
			oldest = item
		}
	}
	s.laneAccess.Unlock()
	if oldest == nil {
		return false
	}
	s.rotateAfter.Store(time.Now().Add(s.config.ReconnectInitialDelay).UnixNano())
	oldest.close()
	return true
}

func (s *Session) rotationReconnectDelay() time.Duration {
	notBefore := time.Unix(0, s.rotateAfter.Load())
	if wait := time.Until(notBefore); wait > 0 {
		return wait
	}
	return 0
}

func (s *Session) removeLane(target *lane) {
	select {
	case <-s.closed:
		return
	default:
	}
	s.laneAccess.Lock()
	current, loaded := s.lanes[target.id]
	if !loaded || current != target {
		s.laneAccess.Unlock()
		return
	}
	delete(s.lanes, target.id)
	s.activeLanes.Store(int64(len(s.lanes)))
	if len(s.lanes) == 0 && s.resumeTimer == nil {
		s.resumeEpoch++
		resumeEpoch := s.resumeEpoch
		s.resumeTimer = time.AfterFunc(s.config.ResumeTimeout, func() {
			s.expireResume(resumeEpoch)
		})
	}
	s.laneAccess.Unlock()
	s.reliable.resetSent()
	s.signalSend()
	s.notifyLaneChange()
}

func (s *Session) expireResume(resumeEpoch uint64) {
	s.laneAccess.Lock()
	currentTimer := s.resumeEpoch == resumeEpoch
	expire := len(s.lanes) == 0 && currentTimer && !s.resumeExpired
	if expire {
		s.resumeExpired = true
	}
	if currentTimer {
		s.resumeTimer = nil
	}
	s.laneAccess.Unlock()
	if expire {
		s.CloseWithError(ErrResumeTimeout)
	}
}

// suspendedWriteLimit bounds how much fresh application data the reliable
// stream accepts while no carrier is available. Accepting the full
// unacknowledged window during an outage would pin max_unacked_bytes per
// session for the whole resume window and delay back pressure until the buffer
// is full; a smaller ceiling stalls the producer within milliseconds and keeps
// only what was genuinely in flight when the carriers disappeared.
func (s *Session) suspendedWriteLimit() int {
	limit := s.config.MaxUnackedBytes / 8
	if limit < StreamChunkSize {
		limit = StreamChunkSize
	}
	return limit
}

func (s *Session) OpenPacket(ctx context.Context, destination M.Socksaddr) (*PacketConn, error) {
	if s.server {
		return nil, errors.New("server cannot initiate an extrojan UDP association")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !destination.IsValid() {
		return nil, errors.New("invalid extrojan UDP destination")
	}
	select {
	case <-s.closed:
		return nil, s.Err()
	default:
	}
	associationID := s.nextAssociation.Add(1)
	if associationID == 0 {
		associationID = s.nextAssociation.Add(1)
	}
	packetConn := newPacketConn(s, associationID, destination)
	s.packetAccess.Lock()
	select {
	case <-s.closed:
		s.packetAccess.Unlock()
		return nil, s.Err()
	default:
	}
	if s.idleClosing {
		s.packetAccess.Unlock()
		return nil, net.ErrClosed
	}
	if len(s.packets)+len(s.pendingPacketCloses) >= s.config.MaxUDPAssociations {
		s.packetAccess.Unlock()
		return nil, errors.New("extrojan UDP association limit reached")
	}
	s.packets[associationID] = packetConn
	s.udpLifecycle = true
	s.packetAccess.Unlock()
	packetConn.startIdleTimer()

	openPayload, err := EncodeUDPOpen(associationID, destination)
	if err != nil {
		packetConn.closeRemote()
		return nil, err
	}
	retryInterval := s.config.RetransmitInterval
	if retryInterval > time.Second {
		retryInterval = time.Second
	}
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()
	for {
		_ = s.sendFrame(FrameUDPOpen, openPayload)
		select {
		case status := <-packetConn.openResult:
			if status == StatusOK {
				return packetConn, nil
			}
			packetConn.closeRemote()
			return nil, fmt.Errorf("extrojan UDP open rejected with status %d", status)
		case <-ticker.C:
		case <-ctx.Done():
			packetConn.close(true, ctx.Err())
			return nil, ctx.Err()
		case <-packetConn.closed:
			return nil, packetConn.err()
		case <-s.closed:
			packetConn.closeRemote()
			return nil, s.Err()
		}
	}
}

func (s *Session) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
	}
	_ = s.writeControlFrame(FrameSessionClose, EncodeSessionClose(0))
	s.CloseWithError(io.EOF)
	return nil
}

func (s *Session) CloseWithError(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	s.closeOnce.Do(func() {
		s.errAccess.Lock()
		s.closeErr = err
		s.errAccess.Unlock()
		close(s.closed)
		s.cancel()

		s.laneAccess.Lock()
		if s.resumeTimer != nil {
			s.resumeTimer.Stop()
			s.resumeTimer = nil
		}
		lanes := make([]*lane, 0, len(s.lanes))
		for _, item := range s.lanes {
			lanes = append(lanes, item)
		}
		s.lanes = make(map[uint32]*lane)
		s.activeLanes.Store(0)
		s.laneAccess.Unlock()
		for _, item := range lanes {
			item.close()
		}

		s.packetAccess.Lock()
		packets := make([]*PacketConn, 0, len(s.packets))
		for _, packetConn := range s.packets {
			packets = append(packets, packetConn)
		}
		s.packetAccess.Unlock()
		for _, packetConn := range packets {
			packetConn.closeRemote()
		}

		s.reliable.notifyRead()
		s.reliable.notifyWrite()
		s.notifyLaneChange()
		if s.onClose != nil {
			s.onClose(s)
		}
	})
}

func (s *Session) Err() error {
	select {
	case <-s.closed:
		s.errAccess.Lock()
		err := s.closeErr
		s.errAccess.Unlock()
		if err == nil {
			return io.ErrClosedPipe
		}
		return err
	default:
		return nil
	}
}

func (s *Session) handleFrame(source *lane, frameType byte, payload []byte) error {
	switch frameType {
	case FrameStreamData:
		offset, data, err := DecodeStreamData(payload)
		if err != nil {
			return err
		}
		nextOffset, err := s.reliable.receive(offset, data)
		if err != nil {
			return err
		}
		s.ackAccess.Lock()
		if !s.ackDirty || nextOffset > s.ackNext {
			s.ackNext = nextOffset
		}
		s.ackDirty = true
		s.ackAccess.Unlock()
		s.signalSend()
		if finOffset, ready := s.reliable.readyFIN(); ready {
			_ = s.sendFrame(FrameStreamFINACK, EncodeUint64(finOffset))
		}
		return nil
	case FrameStreamACK:
		nextOffset, err := DecodeUint64(payload)
		if err != nil {
			return err
		}
		return s.reliable.acknowledge(nextOffset)
	case FrameStreamFIN:
		offset, err := DecodeUint64(payload)
		if err != nil {
			return err
		}
		ready, err := s.reliable.receiveFIN(offset)
		if err != nil {
			return err
		}
		if ready {
			_ = s.sendFrame(FrameStreamFINACK, EncodeUint64(offset))
		}
		return nil
	case FrameStreamFINACK:
		offset, err := DecodeUint64(payload)
		if err != nil {
			return err
		}
		return s.reliable.acknowledgeFIN(offset)
	case FrameUDPOpen:
		return s.handleUDPOpen(payload)
	case FrameUDPOpenACK:
		associationID, status, err := DecodeUDPOpenACK(payload)
		if err != nil {
			return err
		}
		if s.server {
			return errors.New("server received UDP_OPEN_ACK")
		}
		s.packetAccess.Lock()
		packetConn := s.packets[associationID]
		s.packetAccess.Unlock()
		if packetConn != nil {
			packetConn.reportOpen(status)
		}
		return nil
	case FrameUDPData:
		associationID, destination, data, err := DecodeUDPData(payload)
		if err != nil {
			return err
		}
		s.packetAccess.Lock()
		packetConn := s.packets[associationID]
		s.packetAccess.Unlock()
		if packetConn != nil {
			packetConn.deliver(destination, data)
		}
		return nil
	case FrameUDPClose:
		associationID, err := DecodeUint64(payload)
		if err != nil {
			return err
		}
		s.packetAccess.Lock()
		packetConn := s.packets[associationID]
		_, pendingClose := s.pendingPacketCloses[associationID]
		if s.server || packetConn != nil || pendingClose {
			s.recordPacketTombstoneLocked(associationID, time.Now())
		}
		s.packetAccess.Unlock()
		if packetConn != nil {
			packetConn.closeRemote()
		}
		_ = s.sendFrame(FrameUDPCloseACK, EncodeUint64(associationID))
		return nil
	case FrameUDPCloseACK:
		associationID, err := DecodeUint64(payload)
		if err != nil {
			return err
		}
		s.packetAccess.Lock()
		if _, pendingClose := s.pendingPacketCloses[associationID]; pendingClose {
			delete(s.pendingPacketCloses, associationID)
			s.recordPacketTombstoneLocked(associationID, time.Now())
		}
		s.packetAccess.Unlock()
		return nil
	case FramePing:
		if len(payload) != 8 {
			return errors.New("invalid PING payload")
		}
		frame, err := EncodeFrame(FramePong, payload, s.config.MaxFrameSize)
		if err != nil {
			return err
		}
		_ = source.enqueue(frame)
		return nil
	case FramePong:
		if len(payload) != 8 {
			return errors.New("invalid PONG payload")
		}
		return nil
	case FrameSessionClose:
		if len(payload) != 2 {
			return errors.New("invalid SESSION_CLOSE payload")
		}
		s.CloseWithError(io.EOF)
		return nil
	default:
		return fmt.Errorf("unknown extrojan frame type 0x%02x", frameType)
	}
}

func (s *Session) handleUDPOpen(payload []byte) error {
	if !s.server {
		return errors.New("client received UDP_OPEN")
	}
	associationID, destination, err := DecodeUDPOpen(payload)
	if err != nil {
		return err
	}
	if associationID == 0 || !destination.IsValid() {
		return errors.New("invalid extrojan UDP association")
	}
	s.packetAccess.Lock()
	select {
	case <-s.closed:
		s.packetAccess.Unlock()
		return s.Err()
	default:
	}
	if s.packetTombstoneActiveLocked(associationID, time.Now()) {
		s.packetAccess.Unlock()
		_ = s.sendFrame(FrameUDPClose, EncodeUint64(associationID))
		return nil
	}
	if packetConn := s.packets[associationID]; packetConn != nil {
		sameDestination := packetConn.destination == destination
		s.packetAccess.Unlock()
		if !sameDestination {
			return errors.New("conflicting extrojan UDP association")
		}
		_ = s.sendFrame(FrameUDPOpenACK, EncodeUDPOpenACK(associationID, StatusOK))
		return nil
	}
	if _, closing := s.pendingPacketCloses[associationID]; closing {
		s.packetAccess.Unlock()
		// The peer may be retrying UDP_OPEN because its original ACK was
		// lost. Preserve the close tombstone and repeat the terminal state
		// instead of creating a second upstream socket for the same ID.
		_ = s.sendFrame(FrameUDPClose, EncodeUint64(associationID))
		return nil
	}
	if len(s.packets)+len(s.pendingPacketCloses) >= s.config.MaxUDPAssociations {
		s.packetAccess.Unlock()
		_ = s.sendFrame(FrameUDPOpenACK, EncodeUDPOpenACK(associationID, StatusResourceLimit))
		return nil
	}
	packetConn := newPacketConn(s, associationID, destination)
	s.packets[associationID] = packetConn
	s.udpLifecycle = true
	s.packetAccess.Unlock()
	packetConn.startIdleTimer()

	if s.onUDPOpen == nil {
		packetConn.closeRemote()
		_ = s.sendFrame(FrameUDPOpenACK, EncodeUDPOpenACK(associationID, StatusInvalidRequest))
		return nil
	}
	_ = s.sendFrame(FrameUDPOpenACK, EncodeUDPOpenACK(associationID, StatusOK))
	go s.onUDPOpen(s.ctx, packetConn, destination)
	return nil
}

func (s *Session) closePacket(associationID uint64, target *PacketConn, sendClose bool) {
	s.packetAccess.Lock()
	current := s.packets[associationID]
	if current == target {
		delete(s.packets, associationID)
		if sendClose {
			s.pendingPacketCloses[associationID] = time.Time{}
		}
	}
	closeIdle := current == target && s.shouldCloseIdleLocked()
	s.packetAccess.Unlock()
	if current == target && sendClose {
		s.signalSend()
	}
	if closeIdle {
		go s.Close()
	}
}

func (s *Session) shouldCloseIdleLocked() bool {
	if s.server || s.config.UDPIdleTimeout <= 0 || !s.udpLifecycle || s.idleClosing || len(s.packets) != 0 || s.activeStreams != 0 {
		return false
	}
	select {
	case <-s.closed:
		return false
	default:
	}
	s.idleClosing = true
	return true
}

func (s *Session) sendLoop() {
	ticker := time.NewTicker(s.config.RetransmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.sendWake:
		case <-ticker.C:
		case <-s.closed:
			return
		}
		now := time.Now()
		s.purgePacketTombstones(now)
		s.flushPacketCloses(now)
		s.flushACK()
		allQueued := true
		for _, segment := range s.reliable.dueSegments(now) {
			if !s.sendFrame(FrameStreamData, EncodeStreamData(segment.offset, segment.data)) {
				allQueued = false
				break
			}
			s.reliable.markSent(segment.offset, now)
		}
		if allQueued {
			if finOffset, due := s.reliable.dueFIN(now); due && s.sendFrame(FrameStreamFIN, EncodeUint64(finOffset)) {
				s.reliable.markFINSent(now)
			}
		}
	}
}

func (s *Session) packetTombstoneTTL() time.Duration {
	ttl := s.config.ResumeTimeout
	if s.config.LinkTimeout > ttl {
		ttl = s.config.LinkTimeout
	}
	if s.config.ReconnectMaxDelay > ttl {
		ttl = s.config.ReconnectMaxDelay
	}
	return ttl
}

func (s *Session) recordPacketTombstoneLocked(associationID uint64, now time.Time) {
	s.purgePacketTombstonesLocked(now)
	if _, loaded := s.packetTombstones[associationID]; !loaded && len(s.packetTombstones) >= s.config.MaxUDPAssociations {
		var (
			oldestID     uint64
			oldestExpiry time.Time
		)
		for packetID, expiry := range s.packetTombstones {
			if oldestExpiry.IsZero() || expiry.Before(oldestExpiry) {
				oldestID = packetID
				oldestExpiry = expiry
			}
		}
		delete(s.packetTombstones, oldestID)
	}
	s.packetTombstones[associationID] = now.Add(s.packetTombstoneTTL())
}

func (s *Session) packetTombstoneActiveLocked(associationID uint64, now time.Time) bool {
	expiry, loaded := s.packetTombstones[associationID]
	if !loaded {
		return false
	}
	if !now.Before(expiry) {
		delete(s.packetTombstones, associationID)
		return false
	}
	return true
}

func (s *Session) purgePacketTombstones(now time.Time) {
	s.packetAccess.Lock()
	s.purgePacketTombstonesLocked(now)
	s.packetAccess.Unlock()
}

func (s *Session) purgePacketTombstonesLocked(now time.Time) {
	for associationID, expiry := range s.packetTombstones {
		if !now.Before(expiry) {
			delete(s.packetTombstones, associationID)
		}
	}
}

func (s *Session) flushPacketCloses(now time.Time) {
	s.packetAccess.Lock()
	due := make([]uint64, 0, len(s.pendingPacketCloses))
	for associationID, lastSent := range s.pendingPacketCloses {
		if lastSent.IsZero() || now.Sub(lastSent) >= s.config.RetransmitInterval {
			due = append(due, associationID)
		}
	}
	s.packetAccess.Unlock()
	for _, associationID := range due {
		if !s.sendFrame(FrameUDPClose, EncodeUint64(associationID)) {
			return
		}
		s.packetAccess.Lock()
		if _, loaded := s.pendingPacketCloses[associationID]; loaded {
			s.pendingPacketCloses[associationID] = now
		}
		s.packetAccess.Unlock()
	}
}

func (s *Session) reserveUDPBytes(size int) bool {
	if size < 0 {
		return false
	}
	limit := int64(s.config.MaxUDPQueueBytes)
	size64 := int64(size)
	for {
		current := s.udpQueuedBytes.Load()
		if size64 > limit-current {
			return false
		}
		if s.udpQueuedBytes.CompareAndSwap(current, current+size64) {
			return true
		}
	}
}

func (s *Session) releaseUDPBytes(size int) {
	if size > 0 {
		s.udpQueuedBytes.Add(-int64(size))
	}
}

func (s *Session) flushACK() {
	s.ackAccess.Lock()
	if !s.ackDirty {
		s.ackAccess.Unlock()
		return
	}
	nextOffset := s.ackNext
	s.ackAccess.Unlock()
	if !s.sendFrame(FrameStreamACK, EncodeUint64(nextOffset)) {
		return
	}
	s.ackAccess.Lock()
	if s.ackNext == nextOffset {
		s.ackDirty = false
	}
	s.ackAccess.Unlock()
}

func (s *Session) sendFrame(frameType byte, payload []byte) bool {
	frame, err := EncodeFrame(frameType, payload, s.config.MaxFrameSize)
	if err != nil {
		return false
	}
	s.laneAccess.Lock()
	lanes := make([]*lane, 0, len(s.lanes))
	for _, item := range s.lanes {
		if !item.closedFlag.Load() {
			lanes = append(lanes, item)
		}
	}
	s.laneAccess.Unlock()
	if len(lanes) == 0 {
		return false
	}
	start := int((s.roundRobin.Add(1) - 1) % uint64(len(lanes)))
	rotated := append(append(make([]*lane, 0, len(lanes)), lanes[start:]...), lanes[:start]...)
	sort.SliceStable(rotated, func(i, j int) bool {
		return rotated[i].queueBytes.Load() < rotated[j].queueBytes.Load()
	})
	for _, item := range rotated {
		if item.enqueue(frame) {
			return true
		}
	}
	return false
}

func (s *Session) writeControlFrame(frameType byte, payload []byte) bool {
	frame, err := EncodeFrame(frameType, payload, s.config.MaxFrameSize)
	if err != nil {
		return false
	}
	s.laneAccess.Lock()
	lanes := make([]*lane, 0, len(s.lanes))
	for _, item := range s.lanes {
		if !item.closedFlag.Load() {
			lanes = append(lanes, item)
		}
	}
	s.laneAccess.Unlock()
	if len(lanes) == 0 {
		return false
	}
	sort.Slice(lanes, func(i, j int) bool {
		return lanes[i].queueBytes.Load() < lanes[j].queueBytes.Load()
	})
	if err = lanes[0].write(frame); err != nil {
		lanes[0].closeWithError(err)
		return false
	}
	return true
}

func (s *Session) signalSend() {
	select {
	case s.sendWake <- struct{}{}:
	default:
	}
}

func (s *Session) notifyLaneChange() {
	select {
	case s.laneChange <- struct{}{}:
	default:
	}
}

func EncodeSessionClose(code uint16) []byte {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, code)
	return payload
}
