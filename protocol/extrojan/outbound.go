package extrojan

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	trojanProtocol "github.com/sagernet/sing-box/protocol/trojan"
	ext "github.com/sagernet/sing-box/transport/extrojan"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.ExtrojanOutboundOptions](registry, C.TypeExtrojan, NewOutbound)
}

const (
	modeUnknown = iota
	modeExtrojan
	modeLegacy
)

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	tlsConfig  tls.Config
	tlsDialer  tls.Dialer
	transport  adapter.V2RayClientTransport

	client     *ext.Client
	config     ext.Config
	muxSession *yamux.Session
	legacy     adapter.Outbound
	fallback   bool

	sessionAccess    sync.Mutex
	session          *ext.Session
	mode             int
	legacyProbeAfter time.Time

	packetAccess sync.Mutex
	packets      map[*resumablePacketConn]struct{}
	closed       bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ExtrojanOutboundOptions) (adapter.Outbound, error) {
	sessionConfig, err := buildSessionConfig(options.Session)
	if err != nil {
		return nil, E.Cause(err, "invalid extrojan session options")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	instance := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeExtrojan, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		fallback:   options.FallbackToTrojan == nil || *options.FallbackToTrojan,
		config:     sessionConfig,
		packets:    make(map[*resumablePacketConn]struct{}),
	}
	if options.TLS != nil {
		instance.tlsConfig, err = tls.NewClientWithOptions(tls.ClientOptions{
			Context:        ctx,
			Logger:         logger,
			ServerAddress:  options.Server,
			Options:        common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: false,
		})
		if err != nil {
			return nil, err
		}
		instance.tlsDialer = tls.NewDialer(outboundDialer, instance.tlsConfig)
	}
	if options.Transport != nil {
		instance.transport, err = v2ray.NewClientTransport(ctx, instance.dialer, instance.serverAddr, common.PtrValueOrDefault(options.Transport), instance.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}
	instance.client, err = ext.NewClient(sessionConfig, trojan.Key(options.Password), instance.dialCarrier)
	if err != nil {
		return nil, err
	}
	if instance.fallback {
		legacyOutbound, legacyErr := trojanProtocol.NewOutbound(ctx, router, logger, tag+"-legacy", option.TrojanOutboundOptions{
			DialerOptions:               options.DialerOptions,
			ServerOptions:               options.ServerOptions,
			Password:                    options.Password,
			Network:                     options.Network,
			OutboundTLSOptionsContainer: options.OutboundTLSOptionsContainer,
			Multiplex:                   options.Multiplex,
			Transport:                   options.Transport,
		})
		if legacyErr != nil {
			return nil, legacyErr
		}
		instance.legacy = legacyOutbound
	}
	return instance, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		var lastErr error
		for attempt := 0; attempt < 2; attempt++ {
			session, legacy, err := h.ensureSession(ctx)
			if err != nil {
				return nil, err
			}
			if legacy {
				h.logger.InfoContext(ctx, "outbound legacy Trojan connection to ", destination)
				return h.legacy.DialContext(ctx, network, destination)
			}
			h.logger.InfoContext(ctx, "outbound extrojan connection to ", destination)
			h.sessionAccess.Lock()
			muxSession := h.muxSession
			valid := h.session == session && muxSession != nil && !muxSession.IsClosed()
			h.sessionAccess.Unlock()
			if valid {
				lastErr = nil
				var connection net.Conn
				connection, lastErr = openResumableMuxStream(session, muxSession, destination)
				if lastErr == nil {
					return connection, nil
				}
			} else {
				lastErr = net.ErrClosed
			}
			muxClosed := muxSession == nil || muxSession.IsClosed()
			stale := !valid || session.Err() != nil || errors.Is(lastErr, net.ErrClosed) || muxClosed
			if !stale {
				return nil, lastErr
			}
			session.CloseWithError(lastErr)
			h.discardSession(session)
		}
		return nil, lastErr
	case N.NetworkUDP:
		packetConn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bindExtrojanPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func bindExtrojanPacketConn(packetConn net.PacketConn, destination M.Socksaddr) net.Conn {
	return bufio.NewBindPacketConn(packetConn, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	session, legacy, err := h.ensureSession(ctx)
	if err != nil {
		return nil, err
	}
	if legacy {
		h.logger.InfoContext(ctx, "outbound legacy Trojan packet connection to ", destination)
		return h.legacy.ListenPacket(ctx, destination)
	}
	h.logger.InfoContext(ctx, "outbound extrojan packet connection to ", destination)
	packetConn, err := session.OpenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	resumableConn := newResumablePacketConn(ctx, h, destination, packetConn)
	if !h.registerPacketConn(resumableConn) {
		_ = resumableConn.Close()
		return nil, net.ErrClosed
	}
	return resumableConn, nil
}

func (h *Outbound) openExtrojanPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if h.isClosed() {
			return nil, net.ErrClosed
		}
		session, legacy, err := h.ensureSession(ctx)
		if err != nil {
			return nil, err
		}
		if legacy {
			return nil, ext.ErrLegacyServer
		}
		packetConn, openErr := session.OpenPacket(ctx, destination)
		if openErr == nil {
			return packetConn, nil
		}
		if session.Err() == nil && !errors.Is(openErr, net.ErrClosed) {
			return nil, openErr
		}
		session.CloseWithError(openErr)
		h.discardSession(session)
	}
	return nil, net.ErrClosed
}

func (h *Outbound) discardSession(target *ext.Session) {
	h.sessionAccess.Lock()
	if h.session != target {
		h.sessionAccess.Unlock()
		return
	}
	muxSession := h.muxSession
	h.session = nil
	h.muxSession = nil
	h.sessionAccess.Unlock()
	if muxSession != nil {
		_ = muxSession.Close()
	}
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.DropLanes()
	if h.transport != nil {
		_ = h.transport.Close()
	}
	if listener, loaded := h.legacy.(adapter.InterfaceUpdateListener); loaded {
		listener.InterfaceUpdated(ctx)
	}
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if legacy, isLifecycle := h.legacy.(adapter.Lifecycle); isLifecycle {
		err := legacy.Start(stage, scope)
		if err != nil {
			return E.Cause(err, "start legacy Trojan outbound")
		}
	}
	if stage == adapter.StartStateInitialize {
		scope.Add(h.Close)
	}
	return nil
}

func (h *Outbound) Close() error {
	h.packetAccess.Lock()
	if h.closed {
		h.packetAccess.Unlock()
		return nil
	}
	h.closed = true
	packetConns := make([]*resumablePacketConn, 0, len(h.packets))
	for packetConn := range h.packets {
		packetConns = append(packetConns, packetConn)
	}
	h.packets = make(map[*resumablePacketConn]struct{})
	h.packetAccess.Unlock()
	for _, packetConn := range packetConns {
		_ = packetConn.Close()
	}

	h.sessionAccess.Lock()
	muxSession := h.muxSession
	h.muxSession = nil
	h.session = nil
	h.sessionAccess.Unlock()
	if muxSession != nil {
		_ = muxSession.Close()
	}
	return common.Close(
		h.client,
		h.transport,
	)
}

func (h *Outbound) ensureSession(ctx context.Context) (*ext.Session, bool, error) {
	if h.isClosed() {
		return nil, false, net.ErrClosed
	}
	h.sessionAccess.Lock()
	if h.mode == modeLegacy {
		if time.Now().Before(h.legacyProbeAfter) {
			h.sessionAccess.Unlock()
			if h.legacy == nil {
				return nil, false, ext.ErrLegacyServer
			}
			return nil, true, nil
		}
		h.mode = modeUnknown
	}
	if h.session != nil && h.session.Err() == nil && h.muxSession != nil && !h.muxSession.IsClosed() {
		session := h.session
		h.sessionAccess.Unlock()
		return session, false, nil
	}
	staleMuxSession := h.muxSession
	h.session = nil
	h.muxSession = nil
	h.sessionAccess.Unlock()
	if staleMuxSession != nil {
		_ = staleMuxSession.Close()
	}

	// Serialize initial handshakes so simultaneous first TCP and UDP requests
	// share one logical extrojan session.
	h.sessionAccess.Lock()
	defer h.sessionAccess.Unlock()
	if h.mode == modeLegacy {
		if time.Now().Before(h.legacyProbeAfter) {
			if h.legacy == nil {
				return nil, false, ext.ErrLegacyServer
			}
			return nil, true, nil
		}
		h.mode = modeUnknown
	}
	if h.session != nil && h.session.Err() == nil && h.muxSession != nil && !h.muxSession.IsClosed() {
		return h.session, false, nil
	}
	session, err := h.openSession(ctx)
	if err != nil {
		if legacyFallbackAllowed(h.mode, h.fallback, err) {
			h.mode = modeLegacy
			h.legacyProbeAfter = time.Now().Add(time.Minute)
			return nil, true, nil
		}
		return nil, false, err
	}
	if h.isClosed() {
		session.CloseWithError(net.ErrClosed)
		return nil, false, net.ErrClosed
	}
	h.mode = modeExtrojan
	muxSession, err := yamux.Client(session.Stream(), resumableYamuxConfig(session.Config()))
	if err != nil {
		session.CloseWithError(err)
		return nil, false, err
	}
	h.session = session
	h.muxSession = muxSession
	return session, false, nil
}

func (h *Outbound) openSession(ctx context.Context) (*ext.Session, error) {
	attempts := 1
	if h.mode == modeUnknown {
		// A legacy server and a transient carrier reset are indistinguishable
		// during the extension probe. Require consecutive failures before
		// caching legacy mode.
		attempts = 3
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		session, err := h.client.OpenSession(ctx)
		if err == nil {
			return session, nil
		}
		lastErr = err
		if !errors.Is(err, ext.ErrLegacyServer) || attempt == attempts-1 {
			break
		}
		timer := time.NewTimer(h.config.ReconnectInitialDelay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func legacyFallbackAllowed(mode int, fallback bool, err error) bool {
	return fallback && mode != modeExtrojan && errors.Is(err, ext.ErrLegacyServer)
}

func (h *Outbound) dialCarrier(ctx context.Context) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = h.serverAddr
	if h.transport != nil {
		return h.transport.DialContext(ctx)
	}
	if h.tlsDialer != nil {
		return h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	}
	return h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
}

func (h *Outbound) registerPacketConn(packetConn *resumablePacketConn) bool {
	h.packetAccess.Lock()
	defer h.packetAccess.Unlock()
	if h.closed {
		return false
	}
	h.packets[packetConn] = struct{}{}
	return true
}

func (h *Outbound) removePacketConn(packetConn *resumablePacketConn) {
	h.packetAccess.Lock()
	delete(h.packets, packetConn)
	h.packetAccess.Unlock()
}

func (h *Outbound) isClosed() bool {
	h.packetAccess.Lock()
	closed := h.closed
	h.packetAccess.Unlock()
	return closed
}
