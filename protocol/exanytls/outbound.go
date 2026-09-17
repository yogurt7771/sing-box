package exanytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	anySession "github.com/sagernet/sing-box/protocol/exanytls/session"
	ext "github.com/sagernet/sing-box/transport/extrojan"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.ExAnyTLSOutboundOptions](registry, C.TypeExAnyTLS, NewOutbound)
}

const (
	modeUnknown = iota
	modeExAnyTLS
	modeAnyTLS
)

var _ adapter.OutboundWithMultiplex = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx        context.Context
	logger     log.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	tlsConfig  tls.Config
	tlsDialer  tls.Dialer
	transport  adapter.V2RayClientTransport

	client         *ext.Client
	clientOptions  anySession.ClientOptions
	sessionClient  *anySession.Client
	uotClient      *uot.Client
	config         ext.Config
	padding        atomic.TypedValue[*padding.PaddingFactory]
	fallback       bool
	clientMetadata string
	legacyPassword [sha256.Size]byte

	modeAccess sync.Mutex
	mode       int
	probeDone  chan struct{}
	closed     bool
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.ExAnyTLSOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.DialerOptions.TCPFastOpen {
		return nil, E.New("tcp_fast_open is not supported with exanytls outbound")
	}
	sessionConfig, err := buildSessionConfig(options.Session)
	if err != nil {
		return nil, E.Cause(err, "invalid exanytls session options")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	instance := &Outbound{
		Adapter:        outbound.NewAdapterWithDialerOptions(C.TypeExAnyTLS, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:            ctx,
		logger:         logger,
		dialer:         outboundDialer,
		serverAddr:     options.ServerOptions.Build(),
		config:         sessionConfig,
		fallback:       options.FallbackToAnyTLS == nil || *options.FallbackToAnyTLS,
		clientMetadata: options.ClientMetadata,
		legacyPassword: sha256.Sum256([]byte(options.Password)),
	}
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
	if options.Transport != nil {
		instance.transport, err = v2ray.NewClientTransport(ctx, instance.dialer, instance.serverAddr, common.PtrValueOrDefault(options.Transport), instance.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}
	if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &instance.padding) {
		return nil, E.New("incorrect default exanytls padding scheme")
	}
	instance.client, err = ext.NewClient(sessionConfig, trojan.Key(options.Password), instance.dialCarrier)
	if err != nil {
		return nil, err
	}
	anyTLSOptions := buildAnyTLSSessionOptions(sessionConfig)
	anyTLSOptions.ClientMetadata = options.ClientMetadata
	instance.clientOptions = anySession.ClientOptions{
		IdleSessionCheckInterval: options.IdleSessionCheckInterval.Build(),
		IdleSessionTimeout:       options.IdleSessionTimeout.Build(),
		MinIdleSession:           options.MinIdleSession,
		Session:                  anyTLSOptions,
		SessionOptionsFor:        instance.sessionOptionsFor,
	}
	return instance, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	h.sessionClient = anySession.NewClient(h.ctx, h.logger, h.dialSession, &h.padding, h.clientOptions)
	h.uotClient = &uot.Client{
		Dialer:  exAnyTLSDialer(h.createProxy),
		Version: uot.Version,
	}
	scope.Add(h.Close)
	return nil
}

func (h *Outbound) MultiplexEnabled() bool {
	return true
}

func (h *Outbound) createProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	stream, err := h.sessionClient.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	if err = M.SocksaddrSerializer.WriteAddrPort(stream, destination); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

type exAnyTLSDialer func(context.Context, M.Socksaddr) (net.Conn, error)

func (d exAnyTLSDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	return d(ctx, destination)
}

func (d exAnyTLSDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.createProxy(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	default:
		return nil, os.ErrInvalid
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}

// sessionOptionsFor sizes one pooled AnyTLS session against the carrier it was
// given. A resumable carrier negotiates its resume window with the server, so
// the local configuration is not authoritative and the session has to follow
// the value the server chose. A compatible AnyTLS carrier cannot recover at
// all, so it keeps the upstream defaults instead of an inflated budget that
// would only delay reporting a dead connection.
func (h *Outbound) sessionOptionsFor(conn net.Conn) anySession.Options {
	var options anySession.Options
	if resumable, loaded := conn.(interface{ SessionConfig() ext.Config }); loaded {
		options = buildAnyTLSSessionOptions(resumable.SessionConfig())
	}
	options.ClientMetadata = h.clientMetadata
	return options
}

func (h *Outbound) dialSession(ctx context.Context) (net.Conn, error) {
	for {
		h.modeAccess.Lock()
		if h.closed {
			h.modeAccess.Unlock()
			return nil, net.ErrClosed
		}
		selectedMode := h.mode
		if selectedMode != modeUnknown {
			h.modeAccess.Unlock()
			return h.dialSelectedMode(ctx, selectedMode)
		}
		if h.probeDone != nil {
			probeDone := h.probeDone
			h.modeAccess.Unlock()
			select {
			case <-probeDone:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		probeDone := make(chan struct{})
		h.probeDone = probeDone
		h.modeAccess.Unlock()

		conn, negotiatedMode, err := h.probeSession(ctx)
		h.modeAccess.Lock()
		if negotiatedMode != modeUnknown {
			h.mode = negotiatedMode
		}
		h.probeDone = nil
		close(probeDone)
		closed := h.closed
		h.modeAccess.Unlock()
		if closed {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, net.ErrClosed
		}
		return conn, err
	}
}

func (h *Outbound) probeSession(ctx context.Context) (net.Conn, int, error) {
	session, err := h.openExtSession(ctx, 3)
	if err == nil {
		return session.Stream(), modeExAnyTLS, nil
	}
	if !h.fallback || !errors.Is(err, ext.ErrLegacyServer) {
		return nil, modeUnknown, err
	}
	h.logger.InfoContext(ctx, "server does not support ExAnyTLS; using compatible AnyTLS mode")
	conn, legacyErr := h.dialLegacyCarrier(ctx)
	return conn, modeAnyTLS, legacyErr
}

func (h *Outbound) dialSelectedMode(ctx context.Context, selectedMode int) (net.Conn, error) {
	switch selectedMode {
	case modeExAnyTLS:
		session, err := h.openExtSession(ctx, 1)
		if err != nil {
			return nil, err
		}
		return session.Stream(), nil
	case modeAnyTLS:
		return h.dialLegacyCarrier(ctx)
	default:
		return nil, E.New("invalid exanytls mode")
	}
}

func (h *Outbound) openExtSession(ctx context.Context, attempts int) (*ext.Session, error) {
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

func (h *Outbound) dialLegacyCarrier(ctx context.Context) (net.Conn, error) {
	conn, err := h.dialCarrier(ctx)
	if err != nil {
		return nil, err
	}
	header := buf.NewPacket()
	defer header.Release()
	header.Write(h.legacyPassword[:])
	var paddingLength int
	if paddingSizes := h.padding.Load().GenerateRecordPayloadSizes(0); len(paddingSizes) > 0 {
		paddingLength = paddingSizes[0]
	}
	binary.BigEndian.PutUint16(header.Extend(2), uint16(paddingLength))
	if paddingLength > 0 {
		header.WriteZeroN(paddingLength)
	}
	if _, err = header.WriteTo(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (h *Outbound) dialCarrier(ctx context.Context) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = h.serverAddr
	if h.transport != nil {
		return h.transport.DialContext(ctx)
	}
	return h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.DropLanes()
	h.modeAccess.Lock()
	legacyMode := h.mode == modeAnyTLS
	h.modeAccess.Unlock()
	if legacyMode {
		h.sessionClient.Reset()
	}
	if h.transport != nil {
		_ = h.transport.Close()
	}
}

func (h *Outbound) Close() error {
	h.modeAccess.Lock()
	if h.closed {
		h.modeAccess.Unlock()
		return nil
	}
	h.closed = true
	h.modeAccess.Unlock()
	return common.Close(h.sessionClient, h.client, h.transport)
}
