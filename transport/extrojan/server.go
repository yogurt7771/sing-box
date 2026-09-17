package extrojan

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type ServerOptions struct {
	Config    Config
	OnSession func(context.Context, *Session, int, M.Socksaddr)
	OnUDPOpen func(context.Context, int, *PacketConn, M.Socksaddr, M.Socksaddr)
}

type Server struct {
	config Config

	access     sync.Mutex
	sessions   map[SessionID]*Session
	userCounts map[int]int
	nextLaneID atomic.Uint32
	closed     bool

	onSession func(context.Context, *Session, int, M.Socksaddr)
	onUDPOpen func(context.Context, int, *PacketConn, M.Socksaddr, M.Socksaddr)
}

func NewServer(options ServerOptions) (*Server, error) {
	if err := options.Config.Validate(); err != nil {
		return nil, err
	}
	return &Server{
		config:     options.Config,
		sessions:   make(map[SessionID]*Session),
		userCounts: make(map[int]int),
		onSession:  options.OnSession,
		onUDPOpen:  options.OnUDPOpen,
	}, nil
}

func (s *Server) HandleOpen(ctx context.Context, conn net.Conn, user int, source M.Socksaddr) (returnErr error) {
	conn = PrepareHandshakeConn(conn)
	defer func() {
		if returnErr != nil {
			forceCloseCarrier(conn)
		}
	}()
	handshakeDeadline := time.Now().Add(s.config.LinkTimeout)
	if err := setHandshakeDeadline(conn, handshakeDeadline); err != nil {
		return err
	}
	request, err := ReadOpenRequest(conn)
	if err != nil {
		return err
	}
	if request.Version != ProtocolVersion {
		_ = writeWithDeadline(conn, handshakeDeadline, func() error {
			return WriteOpenResponse(conn, OpenResponse{
				Status:  StatusUnsupportedVersion,
				Version: ProtocolVersion,
				Message: "unsupported extrojan version",
			})
		})
		return fmt.Errorf("unsupported extrojan version %d", request.Version)
	}
	if request.Flags != 0 || request.RequestedLanes == 0 || request.RequestedLanes > 16 {
		_ = writeWithDeadline(conn, handshakeDeadline, func() error {
			return WriteOpenResponse(conn, OpenResponse{
				Status:  StatusInvalidRequest,
				Version: ProtocolVersion,
				Message: "invalid extrojan OPEN options",
			})
		})
		return errors.New("invalid extrojan OPEN options")
	}
	sessionConfig := s.config
	if int(request.RequestedLanes) < sessionConfig.Connections {
		sessionConfig.Connections = int(request.RequestedLanes)
	}

	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		_ = writeWithDeadline(conn, handshakeDeadline, func() error {
			return WriteOpenResponse(conn, OpenResponse{
				Status:  StatusResourceLimit,
				Version: ProtocolVersion,
				Message: "server is closed",
			})
		})
		return errors.New("extrojan server is closed")
	}
	if len(s.sessions) >= s.config.MaxSessions || s.userCounts[user] >= s.config.MaxSessionsPerUser {
		s.access.Unlock()
		_ = writeWithDeadline(conn, handshakeDeadline, func() error {
			return WriteOpenResponse(conn, OpenResponse{
				Status:  StatusResourceLimit,
				Version: ProtocolVersion,
				Message: "session limit reached",
			})
		})
		return errors.New("extrojan session limit reached")
	}
	var sessionID SessionID
	for {
		if _, err = rand.Read(sessionID[:]); err != nil {
			s.access.Unlock()
			return err
		}
		if _, loaded := s.sessions[sessionID]; !loaded {
			break
		}
	}
	var resumeToken ResumeToken
	if _, err = rand.Read(resumeToken[:]); err != nil {
		s.access.Unlock()
		return err
	}
	laneID := s.newLaneID()
	session, err := NewSession(SessionOptions{
		Context:     ctx,
		Config:      sessionConfig,
		ID:          sessionID,
		ResumeToken: resumeToken,
		Owner:       user,
		Server:      true,
		LocalAddr:   conn.LocalAddr(),
		RemoteAddr:  conn.RemoteAddr(),
		OnUDPOpen: func(packetContext context.Context, packetConn *PacketConn, destination M.Socksaddr) {
			if s.onUDPOpen != nil {
				s.onUDPOpen(packetContext, user, packetConn, source, destination)
			} else {
				_ = packetConn.Close()
			}
		},
		OnClose: s.removeSession,
	})
	if err != nil {
		s.access.Unlock()
		return err
	}
	s.sessions[sessionID] = session
	s.userCounts[user]++
	s.access.Unlock()

	resumeTimeoutMS := sessionConfig.ResumeTimeout.Milliseconds()
	if resumeTimeoutMS > int64(^uint32(0)) {
		resumeTimeoutMS = int64(^uint32(0))
	}
	err = writeWithDeadline(conn, handshakeDeadline, func() error {
		return WriteOpenResponse(conn, OpenResponse{
			Status:          StatusOK,
			Version:         ProtocolVersion,
			SessionID:       sessionID,
			ResumeToken:     resumeToken,
			LaneID:          laneID,
			ResumeTimeoutMS: uint32(resumeTimeoutMS),
			AcceptedLanes:   uint16(sessionConfig.Connections),
		})
	})
	if err != nil {
		session.CloseWithError(err)
		return err
	}
	if err = setHandshakeDeadline(conn, time.Time{}); err != nil {
		session.CloseWithError(err)
		return err
	}
	if err = session.AddLane(laneID, conn); err != nil {
		session.CloseWithError(err)
		return err
	}
	if s.onSession != nil {
		go s.onSession(session.Context(), session, user, source)
	}
	return nil
}

func (s *Server) HandleJoin(_ context.Context, conn net.Conn, user int) (returnErr error) {
	conn = PrepareHandshakeConn(conn)
	defer func() {
		if returnErr != nil {
			forceCloseCarrier(conn)
		}
	}()
	handshakeDeadline := time.Now().Add(s.config.LinkTimeout)
	if err := setHandshakeDeadline(conn, handshakeDeadline); err != nil {
		return err
	}
	request, err := ReadJoinRequest(conn)
	if err != nil {
		return err
	}
	if request.Version != ProtocolVersion {
		_ = writeWithDeadline(conn, handshakeDeadline, func() error {
			return WriteJoinResponse(conn, JoinResponse{
				Status:  StatusUnsupportedVersion,
				Version: ProtocolVersion,
				Message: "unsupported extrojan version",
			})
		})
		return fmt.Errorf("unsupported extrojan version %d", request.Version)
	}

	s.access.Lock()
	session := s.sessions[request.SessionID]
	s.access.Unlock()
	if session == nil {
		_ = writeWithDeadline(conn, handshakeDeadline, func() error {
			return WriteJoinResponse(conn, JoinResponse{
				Status:  StatusNotFound,
				Version: ProtocolVersion,
				Message: "session not found",
			})
		})
		return errors.New("extrojan session not found")
	}
	expectedToken := session.ResumeToken()
	if session.Owner() != user ||
		subtle.ConstantTimeCompare(expectedToken[:], request.ResumeToken[:]) != 1 {
		_ = writeWithDeadline(conn, handshakeDeadline, func() error {
			return WriteJoinResponse(conn, JoinResponse{
				Status:  StatusUnauthorized,
				Version: ProtocolVersion,
				Message: "invalid resume token",
			})
		})
		return errors.New("invalid extrojan resume token")
	}

	// Keep the limit check and lane installation serialized for this session.
	// This prevents concurrent JOIN requests from all observing spare capacity.
	session.joinAccess.Lock()
	defer session.joinAccess.Unlock()
	select {
	case <-session.Done():
		_ = writeWithDeadline(conn, handshakeDeadline, func() error {
			return WriteJoinResponse(conn, JoinResponse{
				Status:  StatusNotFound,
				Version: ProtocolVersion,
				Message: "session expired",
			})
		})
		return errors.New("extrojan session expired")
	default:
	}
	if session.LaneCount() >= session.config.Connections {
		_ = writeWithDeadline(conn, handshakeDeadline, func() error {
			return WriteJoinResponse(conn, JoinResponse{
				Status:  StatusResourceLimit,
				Version: ProtocolVersion,
				Message: "lane limit reached",
			})
		})
		return errors.New("extrojan lane limit reached")
	}

	laneID := s.newLaneID()
	if err = writeWithDeadline(conn, handshakeDeadline, func() error {
		return WriteJoinResponse(conn, JoinResponse{
			Status:  StatusOK,
			Version: ProtocolVersion,
			LaneID:  laneID,
		})
	}); err != nil {
		return err
	}
	if err = setHandshakeDeadline(conn, time.Time{}); err != nil {
		return err
	}
	return session.AddLane(laneID, conn)
}

func (s *Server) Close() error {
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return nil
	}
	s.closed = true
	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.access.Unlock()
	for _, session := range sessions {
		session.CloseWithError(net.ErrClosed)
	}
	return nil
}

func (s *Server) SessionCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.sessions)
}

func (s *Server) removeSession(session *Session) {
	s.access.Lock()
	if current := s.sessions[session.ID()]; current == session {
		delete(s.sessions, session.ID())
		if s.userCounts[session.Owner()] <= 1 {
			delete(s.userCounts, session.Owner())
		} else {
			s.userCounts[session.Owner()]--
		}
	}
	s.access.Unlock()
}

func (s *Server) newLaneID() uint32 {
	for {
		laneID := s.nextLaneID.Add(1)
		if laneID != 0 {
			return laneID
		}
	}
}
