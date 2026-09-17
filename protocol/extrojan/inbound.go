package extrojan

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	boxmux "github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	ext "github.com/sagernet/sing-box/transport/extrojan"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.ExtrojanInboundOptions](registry, C.TypeExtrojan, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router                   adapter.ConnectionRouterEx
	logger                   log.ContextLogger
	listener                 *listener.Listener
	legacyService            *trojan.Service[int]
	extServer                *ext.Server
	users                    []option.TrojanUser
	keyUsers                 map[[trojan.KeyLength]byte]int
	tlsConfig                tls.ServerConfig
	fallbackAddr             M.Socksaddr
	fallbackAddrTLSNextProto map[string]M.Socksaddr
	transport                adapter.V2RayServerTransport
	handshakeTimeout         time.Duration
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ExtrojanInboundOptions) (adapter.Inbound, error) {
	sessionConfig, err := buildSessionConfig(options.Session)
	if err != nil {
		return nil, E.Cause(err, "invalid extrojan session options")
	}
	instance := &Inbound{
		Adapter:          inbound.NewAdapter(C.TypeExtrojan, tag),
		router:           router,
		logger:           logger,
		users:            options.Users,
		keyUsers:         make(map[[trojan.KeyLength]byte]int),
		handshakeTimeout: sessionConfig.LinkTimeout,
	}
	if options.TLS != nil {
		instance.tlsConfig, err = tls.NewServerWithOptions(tls.ServerOptions{
			Context:        ctx,
			Logger:         logger,
			Options:        common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: false,
		})
		if err != nil {
			return nil, err
		}
	}
	var fallbackHandler N.TCPConnectionHandlerEx
	if options.Fallback != nil && options.Fallback.Server != "" || len(options.FallbackForALPN) > 0 {
		if options.Fallback != nil && options.Fallback.Server != "" {
			instance.fallbackAddr = options.Fallback.Build()
			if !instance.fallbackAddr.IsValid() {
				return nil, E.New("invalid fallback address: ", instance.fallbackAddr)
			}
		}
		if len(options.FallbackForALPN) > 0 {
			if instance.tlsConfig == nil {
				return nil, E.New("fallback for ALPN is not supported without TLS")
			}
			instance.fallbackAddrTLSNextProto = make(map[string]M.Socksaddr)
			for nextProto, destination := range options.FallbackForALPN {
				fallbackAddr := destination.Build()
				if !fallbackAddr.IsValid() {
					return nil, E.New("invalid fallback address for ALPN ", nextProto, ": ", fallbackAddr)
				}
				instance.fallbackAddrTLSNextProto[nextProto] = fallbackAddr
			}
		}
		fallbackHandler = adapter.NewUpstreamContextHandler(instance.fallbackConnection, nil)
	}

	legacyHandler := adapter.NewUpstreamContextHandler(instance.newConnection, instance.newPacketConnection)
	instance.legacyService = trojan.NewService[int](legacyHandler, fallbackHandler, logger)
	err = instance.legacyService.UpdateUsers(common.MapIndexed(options.Users, func(index int, _ option.TrojanUser) int {
		return index
	}), common.Map(options.Users, func(it option.TrojanUser) string {
		return it.Password
	}))
	if err != nil {
		return nil, err
	}
	for index, user := range options.Users {
		key := trojan.Key(user.Password)
		if _, loaded := instance.keyUsers[key]; loaded {
			return nil, E.New("duplicate extrojan password")
		}
		instance.keyUsers[key] = index
	}

	instance.router, err = boxmux.NewRouterWithOptions(instance.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	instance.extServer, err = ext.NewServer(ext.ServerOptions{
		Config: sessionConfig,
		OnSession: func(sessionContext context.Context, session *ext.Session, user int, source M.Socksaddr) {
			sessionContext = auth.ContextWithUser(session.Context(), user)
			instance.serveResumableMux(sessionContext, session, source)
		},
		OnUDPOpen: func(packetContext context.Context, user int, packetConn *ext.PacketConn, source M.Socksaddr, destination M.Socksaddr) {
			packetContext = auth.ContextWithUser(packetContext, user)
			var metadata adapter.InboundContext
			metadata.Source = source
			metadata.Destination = destination
			instance.newPacketConnection(packetContext, packetConn, metadata, nil)
		},
	})
	if err != nil {
		return nil, err
	}
	if options.Transport != nil {
		instance.transport, err = v2ray.NewServerTransport(ctx, logger, common.PtrValueOrDefault(options.Transport), instance.tlsConfig, (*inboundTransportHandler)(instance))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
	}
	instance.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: instance,
	})
	return instance, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(h.Close)
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	if h.transport == nil {
		return h.listener.Start()
	}
	if common.Contains(h.transport.Network(), N.NetworkTCP) {
		tcpListener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		go func() {
			if serveErr := h.transport.Serve(tcpListener); serveErr != nil && !E.IsClosed(serveErr) {
				h.logger.Error("transport serve error: ", serveErr)
			}
		}()
	}
	if common.Contains(h.transport.Network(), N.NetworkUDP) {
		udpConn, err := h.listener.ListenUDP()
		if err != nil {
			return err
		}
		go func() {
			if serveErr := h.transport.ServePacket(udpConn); serveErr != nil && !E.IsClosed(serveErr) {
				h.logger.Error("transport serve error: ", serveErr)
			}
		}()
	}
	return nil
}

func (h *Inbound) Close() error {
	return common.Close(
		h.listener,
		h.tlsConfig,
		h.transport,
		h.extServer,
	)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if onClose != nil {
		onClose = N.OnceClose(onClose)
	}
	if h.tlsConfig != nil && h.transport == nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	conn = ext.PrepareHandshakeConn(conn)
	err := h.handleConnection(adapter.WithContext(ctx, &metadata), conn, metadata, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func (h *Inbound) handleConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	if err := conn.SetReadDeadline(time.Now().Add(h.handshakeTimeout)); err != nil {
		return err
	}
	var key [trojan.KeyLength]byte
	keyLength, err := io.ReadFull(conn, key[:])
	if err != nil {
		if netError, loaded := err.(net.Error); loaded && netError.Timeout() {
			return err
		}
		return h.handleLegacyConnection(ctx, conn, key[:keyLength], metadata.Source, onClose)
	}
	user, authenticated := h.keyUsers[key]
	if !authenticated {
		return h.handleLegacyConnection(ctx, conn, key[:], metadata.Source, onClose)
	}
	var suffix [3]byte
	suffixLength, err := io.ReadFull(conn, suffix[:])
	if err != nil {
		if netError, loaded := err.(net.Error); loaded && netError.Timeout() {
			return err
		}
		header := append(append([]byte(nil), key[:]...), suffix[:suffixLength]...)
		return h.handleLegacyConnection(ctx, conn, header, metadata.Source, onClose)
	}
	header := append(append([]byte(nil), key[:]...), suffix[:]...)
	if !bytes.Equal(suffix[:2], trojan.CRLF) {
		return h.handleLegacyConnection(ctx, conn, header, metadata.Source, onClose)
	}
	command := suffix[2]
	if command != ext.CommandOpen && command != ext.CommandJoin {
		return h.handleLegacyConnection(ctx, conn, header, metadata.Source, onClose)
	}
	ctx = auth.ContextWithUser(ctx, user)
	if onClose != nil {
		conn = &closeCallbackConn{Conn: conn, callback: onClose}
	}
	switch command {
	case ext.CommandOpen:
		return h.extServer.HandleOpen(ctx, conn, user, metadata.Source)
	case ext.CommandJoin:
		return h.extServer.HandleJoin(ctx, conn, user)
	default:
		panic("unreachable")
	}
}

func (h *Inbound) handleLegacyConnection(ctx context.Context, conn net.Conn, header []byte, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	return h.legacyService.NewConnection(ctx, replayConn(conn, header), source, onClose)
}

func replayConn(conn net.Conn, header []byte) net.Conn {
	return bufio.NewCachedConn(conn, buf.As(header).ToOwned())
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded || userIndex < 0 || userIndex >= len(h.users) {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	user := h.users[userIndex].Name
	if user == "" {
		user = F.ToString(userIndex)
	} else {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded || userIndex < 0 || userIndex >= len(h.users) {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	user := h.users[userIndex].Name
	if user == "" {
		user = F.ToString(userIndex)
	} else {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) fallbackConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	var fallbackAddr M.Socksaddr
	if len(h.fallbackAddrTLSNextProto) > 0 {
		if tlsConn, loaded := common.Cast[tls.Conn](conn); loaded {
			connectionState := tlsConn.ConnectionState()
			if connectionState.NegotiatedProtocol != "" {
				var found bool
				fallbackAddr, found = h.fallbackAddrTLSNextProto[connectionState.NegotiatedProtocol]
				if !found {
					N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
					return
				}
			}
		}
	}
	if !fallbackAddr.IsValid() {
		if !h.fallbackAddr.IsValid() {
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
			return
		}
		fallbackAddr = h.fallbackAddr
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Destination = fallbackAddr
	h.logger.InfoContext(ctx, "fallback connection to ", fallbackAddr)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

type closeCallbackConn struct {
	net.Conn
	callback N.CloseHandlerFunc
	once     sync.Once
}

func (c *closeCallbackConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.callback(err)
	})
	return err
}

func (c *closeCallbackConn) Upstream() any {
	return c.Conn
}

var _ adapter.V2RayServerTransportHandler = (*inboundTransportHandler)(nil)

type inboundTransportHandler Inbound

func (h *inboundTransportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	(*Inbound)(h).NewConnection(ctx, conn, metadata, onClose)
}
