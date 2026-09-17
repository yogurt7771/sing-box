package extrojan

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/sagernet/sing-box/option"
	ext "github.com/sagernet/sing-box/transport/extrojan"
	singmux "github.com/sagernet/sing-mux"
	singjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

func TestConfirmedExtrojanDoesNotFallbackOnAmbiguousProbeFailure(t *testing.T) {
	probeErr := errors.Join(ext.ErrLegacyServer, net.ErrClosed)
	if legacyFallbackAllowed(modeExtrojan, true, probeErr) {
		t.Fatal("confirmed extrojan capability was silently downgraded")
	}
	if !legacyFallbackAllowed(modeUnknown, true, probeErr) {
		t.Fatal("initial legacy compatibility fallback was disabled")
	}
	if legacyFallbackAllowed(modeUnknown, false, probeErr) {
		t.Fatal("fallback_to_trojan=false was ignored")
	}
}

func TestResumableYamuxConfigOutlivesCarrierRecovery(t *testing.T) {
	config := ext.DefaultConfig()
	yamuxConfig := resumableYamuxConfig(config)
	if yamuxConfig.EnableKeepAlive {
		t.Fatal("Yamux keepalive can terminate a resumable extrojan session")
	}
	minimum := config.LinkTimeout + config.ResumeTimeout
	if yamuxConfig.ConnectionWriteTimeout <= minimum {
		t.Fatalf("write timeout %v does not cover recovery budget %v", yamuxConfig.ConnectionWriteTimeout, minimum)
	}
	if yamuxConfig.StreamCloseTimeout <= minimum {
		t.Fatalf("stream close timeout %v does not cover recovery budget %v", yamuxConfig.StreamCloseTimeout, minimum)
	}
	if yamuxConfig.StreamOpenTimeout != 0 {
		t.Fatalf("stream open timeout must defer to extrojan session lifetime, got %v", yamuxConfig.StreamOpenTimeout)
	}
}

func TestSessionOptionsJSONRoundTripAndBuild(t *testing.T) {
	content := []byte(`{
		"resume_timeout": "7s",
		"max_unacked_bytes": "2MB",
		"max_receive_bytes": "3MB",
		"max_stream_segments": 128,
		"max_udp_queue_bytes": "4MB",
		"udp_idle_timeout": "2m",
		"lane_rotation_interval": "30m"
	}`)
	var options option.ExtrojanSessionOptions
	if err := singjson.Unmarshal(content, &options); err != nil {
		t.Fatal(err)
	}
	config, err := buildSessionConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	if config.ResumeTimeout != 7*time.Second ||
		config.MaxUnackedBytes != 2*1024*1024 ||
		config.MaxReceiveBytes != 3*1024*1024 ||
		config.MaxStreamSegments != 128 ||
		config.MaxUDPQueueBytes != 4*1024*1024 ||
		config.UDPIdleTimeout != 2*time.Minute ||
		config.LaneRotationInterval != 30*time.Minute {
		t.Fatalf("unexpected built config: %+v", config)
	}
	encoded, err := singjson.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	var decoded option.ExtrojanSessionOptions
	if err = singjson.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := buildSessionConfig(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt != config {
		t.Fatalf("round-trip changed config:\nfirst:  %+v\nsecond: %+v", config, rebuilt)
	}
}

func TestUDPLifecycleOptionsDefaultDisabled(t *testing.T) {
	defaultConfig := ext.DefaultConfig()
	if defaultConfig.UDPIdleTimeout != 0 || defaultConfig.LaneRotationInterval != 0 {
		t.Fatalf(
			"transport defaults changed compatibility behavior: idle=%v rotation=%v",
			defaultConfig.UDPIdleTimeout,
			defaultConfig.LaneRotationInterval,
		)
	}
	builtConfig, err := buildSessionConfig(option.ExtrojanSessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if builtConfig.UDPIdleTimeout != 0 || builtConfig.LaneRotationInterval != 0 {
		t.Fatalf(
			"empty JSON options enabled UDP lifecycle behavior: idle=%v rotation=%v",
			builtConfig.UDPIdleTimeout,
			builtConfig.LaneRotationInterval,
		)
	}
}

func TestServerZeroByteHalfCloseReturnsCleanClientEOF(t *testing.T) {
	clientCarrier, serverCarrier := net.Pipe()
	serverSession, err := yamux.Server(serverCarrier, resumableYamuxConfig(ext.DefaultConfig()))
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	clientSession, err := yamux.Client(clientCarrier, resumableYamuxConfig(ext.DefaultConfig()))
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	serverResult := make(chan error, 1)
	go func() {
		stream, acceptErr := serverSession.AcceptStream()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if _, readErr := singmux.ReadStreamRequest(stream); readErr != nil {
			serverResult <- readErr
			return
		}
		serverResult <- newResumableMuxServerConn(stream).CloseWrite()
	}()

	stream, err := clientSession.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	clientConn := &resumableMuxClientConn{
		framedMuxConn: newFramedMuxConn(stream),
		stream:        stream,
		destination:   M.ParseSocksaddr("127.0.0.1:80"),
	}
	defer clientConn.Close()
	var one [1]byte
	n, readErr := clientConn.Read(one[:])
	if n != 0 || !errors.Is(readErr, io.EOF) {
		t.Fatalf("zero-byte server half-close returned n=%d err=%v, want clean EOF", n, readErr)
	}
	if err = <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestFQDNPacketBindingPreservesDomain(t *testing.T) {
	packetConn := &capturePacketConn{}
	destination := M.ParseSocksaddrHostPort("udp.example", 53)
	conn := bindExtrojanPacketConn(packetConn, destination)
	if _, err := conn.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	actual := M.SocksaddrFromNet(packetConn.destination)
	if actual.Fqdn != destination.Fqdn || actual.Port != destination.Port {
		t.Fatalf("bound destination changed: got %v, want %v", actual, destination)
	}
}

type capturePacketConn struct {
	destination net.Addr
}

func (c *capturePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *capturePacketConn) WriteTo(p []byte, destination net.Addr) (int, error) {
	c.destination = destination
	return len(p), nil
}

func (c *capturePacketConn) Close() error {
	return nil
}

func (c *capturePacketConn) LocalAddr() net.Addr {
	return nil
}

func (c *capturePacketConn) SetDeadline(time.Time) error {
	return nil
}

func (c *capturePacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *capturePacketConn) SetWriteDeadline(time.Time) error {
	return nil
}
