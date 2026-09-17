package exanytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	anySession "github.com/sagernet/sing-box/protocol/exanytls/session"
	ext "github.com/sagernet/sing-box/transport/extrojan"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.ExAnyTLSInboundOptions](registry, C.TypeExAnyTLS, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router           adapter.ConnectionRouterEx
	logger           log.ContextLogger
	listener         *listener.Listener
	tlsConfig        tls.ServerConfig
	transport        adapter.V2RayServerTransport
	extServer        *ext.Server
	legacyService    *anytls.Service
	users            []option.AnyTLSUser
	keyUsers         map[[trojan.KeyLength]byte]int
	legacyKeys       map[[sha256.Size]byte]struct{}
	padding          atomic.TypedValue[*padding.PaddingFactory]
	handshakeTimeout time.Duration
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ExAnyTLSInboundOptions) (adapter.Inbound, error) {
	sessionConfig, err := buildSessionConfig(options.Session)
	if err != nil {
		return nil, E.Cause(err, "invalid exanytls session options")
	}
	instance := &Inbound{
		Adapter:          inbound.NewAdapter(C.TypeExAnyTLS, tag),
		router:           uot.NewRouter(router, logger),
		logger:           logger,
		users:            options.Users,
		keyUsers:         make(map[[trojan.KeyLength]byte]int),
		legacyKeys:       make(map[[sha256.Size]byte]struct{}),
		handshakeTimeout: sessionConfig.LinkTimeout,
	}
	if options.TLS != nil && options.TLS.Enabled {
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
	for index, user := range options.Users {
		key := trojan.Key(user.Password)
		if _, loaded := instance.keyUsers[key]; loaded {
			return nil, E.New("duplicate exanytls password")
		}
		instance.keyUsers[key] = index
		instance.legacyKeys[sha256.Sum256([]byte(user.Password))] = struct{}{}
	}
	paddingScheme := padding.DefaultPaddingScheme
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	}
	if !padding.UpdatePaddingScheme(paddingScheme, &instance.padding) {
		return nil, E.New("incorrect exanytls padding scheme format")
	}
	instance.legacyService, err = anytls.NewService(anytls.ServiceConfig{
		Users: common.Map(options.Users, func(it option.AnyTLSUser) anytls.User {
			return (anytls.User)(it)
		}),
		PaddingScheme: paddingScheme,
		Handler:       (*legacyInboundHandler)(instance),
		Logger:        logger,
	})
	if err != nil {
		return nil, E.Cause(err, "create compatible AnyTLS service")
	}
	instance.extServer, err = ext.NewServer(ext.ServerOptions{
		Config: sessionConfig,
		OnSession: func(sessionContext context.Context, session *ext.Session, user int, source M.Socksaddr) {
			sessionContext = auth.ContextWithUser(sessionContext, user)
			instance.serveSession(sessionContext, session, source)
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
		if !common.Contains(instance.transport.Network(), N.NetworkTCP) {
			return nil, E.New("exanytls requires a TCP-based server transport")
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
	tcpListener, err := h.listener.ListenTCP()
	if err != nil {
		return err
	}
	go func() {
		if serveErr := h.transport.Serve(tcpListener); serveErr != nil && !E.IsClosed(serveErr) {
			h.logger.Error("transport serve error: ", serveErr)
		}
	}()
	return nil
}

func (h *Inbound) Close() error {
	return common.Close(h.listener, h.tlsConfig, h.transport, h.extServer)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if onClose != nil {
		onClose = N.OnceClose(onClose)
	}
	if h.transport == nil && h.tlsConfig != nil {
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
	var prefix [sha256.Size]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return err
	}
	if _, legacy := h.legacyKeys[prefix]; legacy {
		header := make([]byte, sha256.Size+2)
		copy(header, prefix[:])
		if _, err := io.ReadFull(conn, header[sha256.Size:]); err != nil {
			return err
		}
		paddingLength := int(binary.BigEndian.Uint16(header[sha256.Size:]))
		if paddingLength > 0 {
			header = append(header, make([]byte, paddingLength)...)
			if _, err := io.ReadFull(conn, header[sha256.Size+2:]); err != nil {
				return err
			}
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		return h.legacyService.NewConnection(ctx, replayConn(conn, header), metadata.Source, onClose)
	}
	var key [trojan.KeyLength]byte
	copy(key[:], prefix[:])
	if _, err := io.ReadFull(conn, key[len(prefix):]); err != nil {
		return err
	}
	user, authenticated := h.keyUsers[key]
	if !authenticated {
		return E.New("unknown exanytls user")
	}
	var suffix [3]byte
	if _, err := io.ReadFull(conn, suffix[:]); err != nil {
		return err
	}
	if !bytes.Equal(suffix[:2], trojan.CRLF) {
		return E.New("invalid exanytls authentication suffix")
	}
	command := suffix[2]
	if command != ext.CommandOpen && command != ext.CommandJoin {
		return E.New("invalid exanytls session command")
	}
	ctx = auth.ContextWithUser(ctx, user)
	if onClose != nil {
		conn = &closeCallbackConn{Conn: conn, callback: onClose}
	}
	if command == ext.CommandOpen {
		return h.extServer.HandleOpen(ctx, conn, user, metadata.Source)
	}
	return h.extServer.HandleJoin(ctx, conn, user)
}

func replayConn(conn net.Conn, header []byte) net.Conn {
	return bufio.NewCachedConn(conn, buf.As(header).ToOwned())
}

func (h *Inbound) serveSession(ctx context.Context, extSession *ext.Session, source M.Socksaddr) {
	session := anySession.NewServerSession(extSession.Stream(), func(stream *anySession.Stream) {
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			_ = stream.HandshakeFailure(err)
			_ = stream.Close()
			h.logger.ErrorContext(ctx, E.Cause(err, "read exanytls destination"))
			return
		}
		h.newConnection(ctx, stream, source, destination)
	}, &h.padding, h.logger, buildAnyTLSSessionOptions(extSession.Config()))
	session.Run()
	_ = session.Close()
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded || userIndex < 0 || userIndex >= len(h.users) {
		N.CloseOnHandshakeFailure(conn, nil, os.ErrInvalid)
		return
	}
	user := h.users[userIndex].Name
	if user == "" {
		user = F.ToString(userIndex)
	} else {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, nil)
}

type legacyInboundHandler Inbound

func (h *legacyInboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] compatible AnyTLS connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "compatible AnyTLS connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

type closeCallbackConn struct {
	net.Conn
	callback N.CloseHandlerFunc
	once     sync.Once
}

func (c *closeCallbackConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.callback(err) })
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
