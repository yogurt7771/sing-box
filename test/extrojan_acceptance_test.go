package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/coder/websocket"
	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

const (
	extrojanType     = "extrojan"
	extrojanPassword = "extrojan-acceptance-password"
	exAnyTLSType     = "exanytls"
	exAnyTLSPassword = "exanytls-acceptance-password"
)

// These tests deliberately treat extrojan as a black box. The only fault
// injection point is a TCP forwarder between the public outbound and inbound.

func TestExtrojanTCPResumesWithoutLossOrDuplication(t *testing.T) {
	target := newTCPListener(t)
	pair := newProtocolPair(t, extrojanType, extrojanType, target.port(), "3s", []string{extrojanPassword}, extrojanPassword)

	app, err := pair.dialTCP()
	require.NoError(t, err)
	defer app.Close()
	peer := target.accept(t, 5*time.Second)
	defer peer.Close()

	require.NoError(t, app.SetDeadline(time.Now().Add(20*time.Second)))
	require.NoError(t, peer.SetDeadline(time.Now().Add(20*time.Second)))

	clientPayload := deterministicPayload(512*1024, 0x31)
	serverPayload := deterministicPayload(512*1024, 0x92)
	var serverReceived atomic.Int64
	var clientReceived atomic.Int64

	type result struct {
		side string
		data []byte
		err  error
	}
	results := make(chan result, 4)
	go func() {
		err := writeChunked(app, clientPayload, 257, 100*time.Microsecond)
		if err != nil {
			err = fmt.Errorf("payload write: %w", err)
		} else if err = closeWrite(app); err != nil {
			err = fmt.Errorf("half-close: %w", err)
		}
		results <- result{side: "client-write", err: err}
	}()
	go func() {
		err := writeChunked(peer, serverPayload, 331, 100*time.Microsecond)
		if err != nil {
			err = fmt.Errorf("payload write: %w", err)
		} else if err = closeWrite(peer); err != nil {
			err = fmt.Errorf("half-close: %w", err)
		}
		results <- result{side: "server-write", err: err}
	}()
	go func() {
		data, err := readAllCounting(peer, &serverReceived)
		results <- result{side: "server-read", data: data, err: err}
	}()
	go func() {
		data, err := readAllCounting(app, &clientReceived)
		results <- result{side: "client-read", data: data, err: err}
	}()

	for _, boundary := range []int64{4093, 65537, 200003} {
		waitAtomicAtLeast(t, &serverReceived, boundary, 8*time.Second)
		waitAtomicAtLeast(t, &clientReceived, boundary, 8*time.Second)
		pair.proxy.beginOutage()
		time.Sleep(140 * time.Millisecond)
		pair.proxy.endOutage()
	}

	got := make(map[string]result)
	for range 4 {
		select {
		case item := <-results:
			got[item.side] = item
		case <-time.After(15 * time.Second):
			t.Fatal("bidirectional stream did not finish after carrier recovery")
		}
	}
	for _, side := range []string{"client-write", "server-write", "server-read", "client-read"} {
		require.NoError(t, got[side].err, side)
	}
	require.Equal(t, clientPayload, got["server-read"].data, "client-to-server stream changed across resume")
	require.Equal(t, serverPayload, got["client-read"].data, "server-to-client stream changed across resume")
	require.Equal(t, 1, target.acceptedCount(), "resume opened a new target-side TCP connection")
	target.requireNoConnection(t, 200*time.Millisecond)
	require.Greater(t, pair.proxy.acceptedCount(), 1, "no replacement carrier was observed")
}

func TestExAnyTLSPreservesSessionPoolAcrossCarrierRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("exanytls recovery test")
	}

	caPEM, certificatePEM, keyPEM := createSelfSignedCertificate(t, "example.org")
	target := newTCPEchoTarget(t)
	targetProxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(target.port())))

	sessionOptions := map[string]any{
		"connections":             1,
		"resume_timeout":          "8s",
		"heartbeat_interval":      "50ms",
		"link_timeout":            "250ms",
		"retransmit_interval":     "40ms",
		"reconnect_initial_delay": "20ms",
		"reconnect_max_delay":     "100ms",
	}
	serverPort := freeTCPPort(t)
	startSettledInstance(t, decodeOptions(t, map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        exAnyTLSType,
				"listen":      "127.0.0.1",
				"listen_port": serverPort,
				"users": []any{
					map[string]any{"name": "acceptance", "password": exAnyTLSPassword},
				},
				"tls": map[string]any{
					"enabled":          true,
					"server_name":      "example.org",
					"certificate_path": certificatePEM,
					"key_path":         keyPEM,
				},
				"transport": map[string]any{
					"type": "ws",
					"path": "/exanytls-resume",
				},
				"session": sessionOptions,
			},
		},
		"outbounds": []any{map[string]any{"type": "direct"}},
	}))
	carrierProxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))

	clientPort := freeTCPPort(t)
	startSettledInstance(t, decodeOptions(t, map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"listen":      "127.0.0.1",
				"listen_port": clientPort,
			},
		},
		"outbounds": []any{
			map[string]any{
				"type":                        exAnyTLSType,
				"server":                      "127.0.0.1",
				"server_port":                 carrierProxy.port(),
				"password":                    exAnyTLSPassword,
				"idle_session_check_interval": "6s",
				"idle_session_timeout":        "6s",
				"min_idle_session":            1,
				"tls": map[string]any{
					"enabled":          true,
					"server_name":      "example.org",
					"certificate_path": caPEM,
				},
				"transport": map[string]any{
					"type": "ws",
					"path": "/exanytls-resume",
					"headers": map[string]any{
						"Host": "example.org",
					},
				},
				"session": sessionOptions,
			},
		},
	}))

	pair := &protocolPair{
		clientPort: clientPort,
		targetPort: targetProxy.port(),
		serverPort: serverPort,
		proxy:      carrierProxy,
	}
	app, err := pair.dialTCP()
	require.NoError(t, err)
	defer app.Close()
	secondApp, err := pair.dialTCP()
	require.NoError(t, err)
	defer secondApp.Close()
	require.NoError(t, writeFull(secondApp, []byte("second-stream-before-outage")))
	requireReadExactly(t, secondApp, []byte("second-stream-before-outage"))
	warmIdleApp, err := pair.dialTCP()
	require.NoError(t, err)
	require.NoError(t, warmIdleApp.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, writeFull(warmIdleApp, []byte("warm-idle-session")))
	requireReadExactly(t, warmIdleApp, []byte("warm-idle-session"))
	require.NoError(t, warmIdleApp.Close())
	waitCondition(t, time.Second, func() bool { return carrierProxy.activeCount() == 3 }, "AnyTLS session pool did not retain three independent resumable sessions")

	payloadSize := int64(8 * 1024 * 1024)
	transferDeadline := 45 * time.Second
	boundaryTimeout := 10 * time.Second
	resultTimeout := 20 * time.Second
	chunkPause := 100 * time.Microsecond
	if os.Getenv("EXANYTLS_LONG_TEST") != "" {
		payloadSize = 1 << 30
		transferDeadline = 5 * time.Minute
		boundaryTimeout = time.Minute
		resultTimeout = 2 * time.Minute
		chunkPause = 0
	}
	require.NoError(t, app.SetDeadline(time.Now().Add(transferDeadline)))
	require.NoError(t, secondApp.SetDeadline(time.Now().Add(transferDeadline)))

	var receivedBytes atomic.Int64
	type transferResult struct {
		bytes int64
		hash  [sha256.Size]byte
		err   error
	}
	writeResult := make(chan transferResult, 1)
	readResult := make(chan transferResult, 1)
	endMarker := []byte("|exanytls-transfer-complete|")
	transferStarted := time.Now()
	go func() {
		hasher := sha256.New()
		buffer := make([]byte, 64*1024)
		state := uint32(0x7a) + 1
		var sent int64
		var writeErr error
		for sent < payloadSize {
			chunkSize := len(buffer)
			if remaining := payloadSize - sent; int64(chunkSize) > remaining {
				chunkSize = int(remaining)
			}
			for index := range buffer[:chunkSize] {
				state = state*1664525 + 1013904223
				buffer[index] = byte(state >> 24)
			}
			_, _ = hasher.Write(buffer[:chunkSize])
			writeErr = writeFull(app, buffer[:chunkSize])
			if writeErr != nil {
				break
			}
			sent += int64(chunkSize)
			if chunkPause > 0 {
				time.Sleep(chunkPause)
			}
		}
		if writeErr == nil {
			writeErr = writeFull(app, endMarker)
		}
		var sum [sha256.Size]byte
		copy(sum[:], hasher.Sum(nil))
		writeResult <- transferResult{bytes: sent, hash: sum, err: writeErr}
	}()
	go func() {
		hasher := sha256.New()
		buffer := make([]byte, 64*1024)
		var received int64
		var readErr error
		for received < payloadSize {
			readBuffer := buffer
			if remaining := payloadSize - received; int64(len(readBuffer)) > remaining {
				readBuffer = readBuffer[:remaining]
			}
			n, err := app.Read(readBuffer)
			if n > 0 {
				received += int64(n)
				receivedBytes.Store(received)
				_, _ = hasher.Write(readBuffer[:n])
			}
			if err != nil {
				readErr = err
				break
			}
		}
		if readErr == nil {
			marker := make([]byte, len(endMarker))
			_, readErr = io.ReadFull(app, marker)
			if readErr == nil && !bytes.Equal(marker, endMarker) {
				readErr = fmt.Errorf("ExAnyTLS end marker changed across carrier recovery")
			}
		}
		var sum [sha256.Size]byte
		copy(sum[:], hasher.Sum(nil))
		readResult <- transferResult{bytes: received, hash: sum, err: readErr}
	}()

	var outageOpenedApp net.Conn
	for outageIndex, boundary := range []int64{payloadSize / 16, payloadSize / 4, payloadSize / 2, payloadSize * 3 / 4} {
		waitAtomicAtLeast(t, &receivedBytes, boundary, boundaryTimeout)
		carrierProxy.beginOutage()
		waitCondition(t, time.Second, func() bool { return carrierProxy.activeCount() == 0 }, "carrier did not enter full outage")
		if outageIndex == 0 {
			type dialResult struct {
				conn net.Conn
				err  error
			}
			pendingDial := make(chan dialResult, 1)
			go func() {
				conn, dialErr := pair.dialTCPWithTimeout(12 * time.Second)
				pendingDial <- dialResult{conn: conn, err: dialErr}
			}()
			// This exceeds sing-anytls v0.0.11's fixed 3s SYNACK watchdog
			// and 5s control-write deadline, but remains inside the 8s
			// resumable-session window.
			time.Sleep(5500 * time.Millisecond)
			carrierProxy.endOutage()
			select {
			case result := <-pendingDial:
				require.NoError(t, result.err, "stream opened during a recoverable outage")
				outageOpenedApp = result.conn
				require.NoError(t, outageOpenedApp.SetDeadline(time.Now().Add(transferDeadline)))
				defer outageOpenedApp.Close()
				require.NoError(t, writeFull(outageOpenedApp, []byte("opened-during-outage")))
				requireReadExactly(t, outageOpenedApp, []byte("opened-during-outage"))
			case <-time.After(5 * time.Second):
				t.Fatal("stream opened during outage did not finish after carrier recovery")
			}
			continue
		}
		time.Sleep(180 * time.Millisecond)
		carrierProxy.endOutage()
	}

	var sent transferResult
	select {
	case sent = <-writeResult:
		require.NoError(t, sent.err)
	case <-time.After(resultTimeout):
		t.Fatal("ExAnyTLS upload did not finish after carrier recovery")
	}
	var received transferResult
	select {
	case received = <-readResult:
		require.NoError(t, received.err)
	case <-time.After(resultTimeout):
		t.Fatal("ExAnyTLS download did not finish after carrier recovery")
	}
	require.Equal(t, payloadSize, sent.bytes, "ExAnyTLS upload length changed across carrier recovery")
	require.Equal(t, payloadSize, received.bytes, "ExAnyTLS download length changed across carrier recovery")
	require.Equal(t, sent.hash, received.hash, "ExAnyTLS stream SHA-256 changed across carrier recovery")
	require.NoError(t, writeFull(app, []byte("still-open-after-recovery")))
	requireReadExactly(t, app, []byte("still-open-after-recovery"))
	require.NoError(t, writeFull(secondApp, []byte("second-stream-after-recovery")))
	requireReadExactly(t, secondApp, []byte("second-stream-after-recovery"))
	require.NotNil(t, outageOpenedApp)
	require.NoError(t, writeFull(outageOpenedApp, []byte("outage-stream-after-recovery")))
	requireReadExactly(t, outageOpenedApp, []byte("outage-stream-after-recovery"))
	require.Equal(t, 4, targetProxy.acceptedCount(), "an established target-side TCP connection was re-created")
	require.GreaterOrEqual(t, carrierProxy.acceptedCount(), 5, "not every outage caused a replacement TLS carrier")
	require.LessOrEqual(t, carrierProxy.peakActiveCount(), 3, "a pooled AnyTLS session exceeded session.connections: 1")
	firstCarrierBytes := carrierProxy.firstClientBytesAfter(nil)
	require.GreaterOrEqual(t, len(firstCarrierBytes), 3)
	require.Equal(t, byte(0x16), firstCarrierBytes[0], "carrier did not start with a TLS handshake record")
	require.Equal(t, byte(0x03), firstCarrierBytes[1], "carrier did not use TLS")
	elapsed := time.Since(transferStarted)
	t.Logf("ExAnyTLS transferred %d bytes in %s (%.1f MiB/s), SHA-256 %s, carrier connections %d, peak active %d", payloadSize, elapsed.Round(time.Millisecond), float64(payloadSize)/(1024*1024)/elapsed.Seconds(), hex.EncodeToString(received.hash[:]), carrierProxy.acceptedCount(), carrierProxy.peakActiveCount())
}

func TestExAnyTLSInheritsAnyTLSUDPOverTCP(t *testing.T) {
	caPEM, certificatePEM, keyPEM := createSelfSignedCertificate(t, "example.org")
	target := newUDPEchoTarget(t)
	sessionOptions := map[string]any{
		"connections":             1,
		"resume_timeout":          "3s",
		"heartbeat_interval":      "50ms",
		"link_timeout":            "250ms",
		"retransmit_interval":     "40ms",
		"reconnect_initial_delay": "20ms",
		"reconnect_max_delay":     "100ms",
	}

	serverPort := freeTCPPort(t)
	startSettledInstance(t, decodeOptions(t, map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        exAnyTLSType,
				"listen":      "127.0.0.1",
				"listen_port": serverPort,
				"users": []any{
					map[string]any{"name": "udp", "password": exAnyTLSPassword},
				},
				"tls": map[string]any{
					"enabled":          true,
					"server_name":      "example.org",
					"certificate_path": certificatePEM,
					"key_path":         keyPEM,
				},
				"session": sessionOptions,
			},
		},
		"outbounds": []any{map[string]any{"type": "direct"}},
	}))
	carrierProxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))

	clientPort := freeTCPPort(t)
	startSettledInstance(t, decodeOptions(t, map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"listen":      "127.0.0.1",
				"listen_port": clientPort,
			},
		},
		"outbounds": []any{
			map[string]any{
				"type":        exAnyTLSType,
				"server":      "127.0.0.1",
				"server_port": carrierProxy.port(),
				"password":    exAnyTLSPassword,
				"tls": map[string]any{
					"enabled":          true,
					"server_name":      "example.org",
					"certificate_path": caPEM,
				},
				"session": sessionOptions,
			},
		},
	}))

	pair := &protocolPair{
		clientPort: clientPort,
		serverPort: serverPort,
		targetPort: target.port(),
		proxy:      carrierProxy,
	}
	packetConn, err := pair.listenPacket()
	require.NoError(t, err)
	defer packetConn.Close()
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, udpRoundTrip(packetConn, target.addr(), []byte("uot-before-outage")))
	waitCondition(t, time.Second, func() bool { return carrierProxy.activeCount() == 1 }, "UoT did not use one pooled AnyTLS session")

	carrierProxy.beginOutage()
	waitCondition(t, time.Second, func() bool { return carrierProxy.activeCount() == 0 }, "UoT carrier did not enter outage")
	time.Sleep(400 * time.Millisecond)
	carrierProxy.endOutage()
	var recoveryErr error
	for recoveryDeadline := time.Now().Add(5 * time.Second); time.Now().Before(recoveryDeadline); {
		require.NoError(t, packetConn.SetDeadline(time.Now().Add(700*time.Millisecond)))
		recoveryErr = udpRoundTrip(packetConn, target.addr(), []byte("uot-after-outage"))
		if recoveryErr == nil {
			break
		}
	}
	require.NoError(t, recoveryErr, "AnyTLS UoT association did not survive a recoverable carrier outage")
	require.Greater(t, carrierProxy.acceptedCount(), 1, "UoT recovery did not replace the TLS carrier")
	require.LessOrEqual(t, carrierProxy.peakActiveCount(), 1, "one UoT stream exceeded session.connections: 1")
}

func TestExAnyTLSAnyTLSBidirectionalCompatibility(t *testing.T) {
	caPEM, certificatePEM, keyPEM := createSelfSignedCertificate(t, "example.org")
	sessionOptions := map[string]any{
		"connections":             1,
		"resume_timeout":          "2s",
		"heartbeat_interval":      "50ms",
		"link_timeout":            "250ms",
		"legacy_probe_timeout":    "500ms",
		"reconnect_initial_delay": "20ms",
		"reconnect_max_delay":     "100ms",
	}
	for _, testCase := range []struct {
		name       string
		clientType string
		serverType string
	}{
		{name: "AnyTLS-client-to-ExAnyTLS-server", clientType: "anytls", serverType: exAnyTLSType},
		{name: "ExAnyTLS-client-to-AnyTLS-server", clientType: exAnyTLSType, serverType: "anytls"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			target := newTCPEchoTarget(t)
			targetProxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(target.port())))
			serverPort := freeTCPPort(t)
			serverInbound := map[string]any{
				"type":        testCase.serverType,
				"listen":      "127.0.0.1",
				"listen_port": serverPort,
				"users": []any{
					map[string]any{"name": "compatible", "password": exAnyTLSPassword},
				},
				"tls": map[string]any{
					"enabled":          true,
					"server_name":      "example.org",
					"certificate_path": certificatePEM,
					"key_path":         keyPEM,
				},
			}
			if testCase.serverType == exAnyTLSType {
				serverInbound["session"] = sessionOptions
			}
			startSettledInstance(t, decodeOptions(t, map[string]any{
				"inbounds":  []any{serverInbound},
				"outbounds": []any{map[string]any{"type": "direct"}},
			}))

			carrierProxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))
			clientPort := freeTCPPort(t)
			clientOutbound := map[string]any{
				"type":        testCase.clientType,
				"server":      "127.0.0.1",
				"server_port": carrierProxy.port(),
				"password":    exAnyTLSPassword,
				"tls": map[string]any{
					"enabled":          true,
					"server_name":      "example.org",
					"certificate_path": caPEM,
				},
			}
			if testCase.clientType == exAnyTLSType {
				clientOutbound["fallback_to_anytls"] = true
				clientOutbound["session"] = sessionOptions
			}
			startSettledInstance(t, decodeOptions(t, map[string]any{
				"inbounds": []any{
					map[string]any{
						"type":        "mixed",
						"listen":      "127.0.0.1",
						"listen_port": clientPort,
					},
				},
				"outbounds": []any{clientOutbound},
			}))

			pair := &protocolPair{
				clientPort: clientPort,
				targetPort: targetProxy.port(),
				serverPort: serverPort,
				proxy:      carrierProxy,
			}
			for streamIndex := 0; streamIndex < 2; streamIndex++ {
				app, err := pair.dialTCP()
				require.NoError(t, err)
				require.NoError(t, app.SetDeadline(time.Now().Add(5*time.Second)))
				message := []byte(fmt.Sprintf("compatible-stream-%d", streamIndex))
				require.NoError(t, writeFull(app, message))
				requireReadExactly(t, app, message)
				require.NoError(t, app.Close())
			}

			waitCondition(t, time.Second, func() bool { return carrierProxy.activeCount() == 1 }, "compatible mode did not settle on one TLS carrier")
			require.LessOrEqual(t, carrierProxy.peakActiveCount(), 1, "compatibility probing exceeded one simultaneous carrier")
			require.Equal(t, 2, targetProxy.acceptedCount(), "compatibility mode did not preserve logical TCP stream boundaries")
			if testCase.clientType == exAnyTLSType {
				require.GreaterOrEqual(t, carrierProxy.acceptedCount(), 4, "ExAnyTLS client did not probe then fall back to AnyTLS")
			} else {
				require.Equal(t, 1, carrierProxy.acceptedCount(), "AnyTLS client required an unnecessary retry against ExAnyTLS server")
			}
		})
	}
}

func TestExAnyTLSServerAcceptsAnyTLSOverWebSocket(t *testing.T) {
	caPEM, certificatePEM, keyPEM := createSelfSignedCertificate(t, "example.org")
	target := newTCPEchoTarget(t)
	targetProxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(target.port())))
	serverPort := freeTCPPort(t)
	startSettledInstance(t, decodeOptions(t, map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        exAnyTLSType,
				"listen":      "127.0.0.1",
				"listen_port": serverPort,
				"users": []any{
					map[string]any{"name": "compatible-ws", "password": exAnyTLSPassword},
				},
				"tls": map[string]any{
					"enabled":          true,
					"server_name":      "example.org",
					"certificate_path": certificatePEM,
					"key_path":         keyPEM,
				},
				"transport": map[string]any{
					"type": "ws",
					"path": "/anytls-compatible",
				},
				"session": map[string]any{
					"connections":        1,
					"resume_timeout":     "2s",
					"heartbeat_interval": "50ms",
					"link_timeout":       "250ms",
				},
			},
		},
		"outbounds": []any{map[string]any{"type": "direct"}},
	}))
	carrierProxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))

	caContent, err := os.ReadFile(caPEM)
	require.NoError(t, err)
	rootCAs := x509.NewCertPool()
	require.True(t, rootCAs.AppendCertsFromPEM(caContent))
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &stdtls.Config{
			RootCAs:    rootCAs,
			ServerName: "example.org",
			MinVersion: stdtls.VersionTLS12,
		},
	}}
	clientContext, cancelClient := context.WithCancel(context.Background())
	t.Cleanup(cancelClient)
	legacyClient, err := anytls.NewClient(clientContext, anytls.ClientConfig{
		Password: exAnyTLSPassword,
		DialOut: func(dialContext context.Context) (net.Conn, error) {
			websocketConn, _, dialErr := websocket.Dial(
				dialContext,
				fmt.Sprintf("wss://127.0.0.1:%d/anytls-compatible", carrierProxy.port()),
				&websocket.DialOptions{HTTPClient: httpClient, Host: "example.org"},
			)
			if dialErr != nil {
				return nil, dialErr
			}
			return websocket.NetConn(clientContext, websocketConn, websocket.MessageBinary), nil
		},
		Logger: logger.NOP(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = legacyClient.Close() })

	for streamIndex := 0; streamIndex < 2; streamIndex++ {
		streamContext, cancelStream := context.WithTimeout(context.Background(), 5*time.Second)
		stream, streamErr := legacyClient.CreateProxy(streamContext, M.ParseSocksaddrHostPort("127.0.0.1", targetProxy.port()))
		cancelStream()
		require.NoError(t, streamErr)
		require.NoError(t, stream.SetDeadline(time.Now().Add(5*time.Second)))
		message := []byte(fmt.Sprintf("compatible-ws-stream-%d", streamIndex))
		require.NoError(t, writeFull(stream, message))
		requireReadExactly(t, stream, message)
		require.NoError(t, stream.Close())
	}

	waitCondition(t, time.Second, func() bool { return carrierProxy.activeCount() == 1 }, "AnyTLS over WebSocket did not retain one carrier")
	require.Equal(t, 1, carrierProxy.acceptedCount(), "AnyTLS over WebSocket retried against ExAnyTLS server")
	require.LessOrEqual(t, carrierProxy.peakActiveCount(), 1)
	require.Equal(t, 2, targetProxy.acceptedCount())
}

func TestExtrojanWritesAndHalfClosesDuringOutage(t *testing.T) {
	target := newTCPListener(t)
	pair := newProtocolPair(t, extrojanType, extrojanType, target.port(), "2s", []string{extrojanPassword}, extrojanPassword)

	app, err := pair.dialTCP()
	require.NoError(t, err)
	defer app.Close()
	peer := target.accept(t, 5*time.Second)
	defer peer.Close()
	require.NoError(t, app.SetDeadline(time.Now().Add(10*time.Second)))
	require.NoError(t, peer.SetDeadline(time.Now().Add(10*time.Second)))

	require.NoError(t, writeFull(app, []byte("client-before|")))
	require.NoError(t, writeFull(peer, []byte("server-before|")))
	requireReadExactly(t, peer, []byte("client-before|"))
	requireReadExactly(t, app, []byte("server-before|"))

	pair.proxy.beginOutage()
	waitCondition(t, 2*time.Second, func() bool { return pair.proxy.activeCount() == 0 }, "carriers did not close")

	clientDone := make(chan error, 1)
	serverDone := make(chan error, 1)
	go func() {
		err := writeFull(app, []byte("client-during-outage"))
		if err == nil {
			err = closeWrite(app)
		}
		clientDone <- err
	}()
	go func() {
		err := writeFull(peer, []byte("server-during-outage"))
		if err == nil {
			err = closeWrite(peer)
		}
		serverDone <- err
	}()

	time.Sleep(200 * time.Millisecond)
	pair.proxy.endOutage()
	require.NoError(t, <-clientDone)
	require.NoError(t, <-serverDone)

	clientRest, err := io.ReadAll(app)
	require.NoError(t, err)
	serverRest, err := io.ReadAll(peer)
	require.NoError(t, err)
	require.Equal(t, []byte("server-during-outage"), clientRest)
	require.Equal(t, []byte("client-during-outage"), serverRest)
	require.Equal(t, 1, target.acceptedCount(), "half-close recovery replaced the application connection")
	target.requireNoConnection(t, 200*time.Millisecond)
}

func TestExtrojanResumesPastUnderlyingMuxTimeouts(t *testing.T) {
	target := newTCPListener(t)
	sessionOptions := map[string]any{
		"resume_timeout":          "50s",
		"heartbeat_interval":      "100ms",
		"link_timeout":            "500ms",
		"retransmit_interval":     "100ms",
		"reconnect_initial_delay": "50ms",
		"reconnect_max_delay":     "200ms",
		"max_unacked_bytes":       "64KB",
		"max_receive_bytes":       "64KB",
	}
	pair := newProtocolPairWithSession(t, extrojanType, extrojanType, target.port(), sessionOptions, []string{extrojanPassword}, extrojanPassword)

	app, err := pair.dialTCP()
	require.NoError(t, err)
	defer app.Close()
	peer := target.accept(t, 5*time.Second)
	defer peer.Close()
	require.NoError(t, app.SetDeadline(time.Now().Add(65*time.Second)))
	require.NoError(t, peer.SetDeadline(time.Now().Add(65*time.Second)))

	require.NoError(t, writeFull(app, []byte("ready")))
	requireReadExactly(t, peer, []byte("ready"))
	pair.proxy.beginOutage()
	waitCondition(t, 3*time.Second, func() bool { return pair.proxy.activeCount() == 0 }, "carriers did not close")

	clientPayload := deterministicPayload(512*1024, 0x46)
	serverPayload := deterministicPayload(512*1024, 0xb3)
	type result struct {
		side string
		data []byte
		err  error
	}
	results := make(chan result, 4)
	go func() {
		writeErr := writeFull(app, clientPayload)
		if writeErr == nil {
			writeErr = closeWrite(app)
		}
		results <- result{side: "client-write", err: writeErr}
	}()
	go func() {
		writeErr := writeFull(peer, serverPayload)
		if writeErr == nil {
			writeErr = closeWrite(peer)
		}
		results <- result{side: "server-write", err: writeErr}
	}()
	go func() {
		data, readErr := io.ReadAll(peer)
		results <- result{side: "server-read", data: data, err: readErr}
	}()
	go func() {
		data, readErr := io.ReadAll(app)
		results <- result{side: "client-read", data: data, err: readErr}
	}()

	// This exceeds Yamux's former 5s stream-close timeout and its
	// 30s keepalive + 10s response timeout.
	time.Sleep(41 * time.Second)
	pair.proxy.endOutage()

	got := make(map[string]result)
	for range 4 {
		select {
		case item := <-results:
			got[item.side] = item
		case <-time.After(20 * time.Second):
			t.Fatal("long-outage stream did not finish after carrier recovery")
		}
	}
	for _, side := range []string{"client-write", "server-write", "server-read", "client-read"} {
		require.NoError(t, got[side].err, side)
	}
	require.Equal(t, clientPayload, got["server-read"].data)
	require.Equal(t, serverPayload, got["client-read"].data)
	require.Equal(t, 1, target.acceptedCount(), "long recovery replaced the target-side TCP connection")
}

func TestExtrojanResumeTimeoutClosesDeterministically(t *testing.T) {
	target := newTCPListener(t)
	pair := newProtocolPair(t, extrojanType, extrojanType, target.port(), "350ms", []string{extrojanPassword}, extrojanPassword)

	app, err := pair.dialTCP()
	require.NoError(t, err)
	defer app.Close()
	peer := target.accept(t, 5*time.Second)
	defer peer.Close()

	require.NoError(t, writeFull(app, []byte("ready")))
	requireReadExactly(t, peer, []byte("ready"))
	pair.proxy.beginOutage()

	appClosed := make(chan error, 1)
	go func() {
		_ = app.SetReadDeadline(time.Now().Add(3 * time.Second))
		var one [1]byte
		_, readErr := app.Read(one[:])
		appClosed <- readErr
	}()
	select {
	case readErr := <-appClosed:
		require.Error(t, readErr, "application connection remained readable after resume timeout")
		require.False(t, errors.Is(readErr, os.ErrDeadlineExceeded), "closure was caused only by the test deadline")
	case <-time.After(2 * time.Second):
		t.Fatal("application connection remained hung beyond resume timeout")
	}

	require.NoError(t, peer.SetReadDeadline(time.Now().Add(2*time.Second)))
	var one [1]byte
	_, peerErr := peer.Read(one[:])
	require.Error(t, peerErr, "target connection remained open beyond resume timeout")
	require.False(t, errors.Is(peerErr, os.ErrDeadlineExceeded), "target closure was caused only by the test deadline")
}

func TestExtrojanServerRestartRejectsStaleSessionAndAcceptsFreshTraffic(t *testing.T) {
	echo := newTCPEchoTarget(t)
	serverPort := freeTCPPort(t)
	sessionOptions := map[string]any{
		"connections":             2,
		"resume_timeout":          "5s",
		"heartbeat_interval":      "50ms",
		"link_timeout":            "250ms",
		"reconnect_initial_delay": "20ms",
		"reconnect_max_delay":     "100ms",
	}
	server := startServerOnlyWithSession(t, extrojanType, serverPort, sessionOptions, []string{extrojanPassword})
	proxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))
	clientPort := freeTCPPort(t)
	startClientOnlyWithSession(t, extrojanType, clientPort, proxy.port(), sessionOptions, extrojanPassword)
	pair := &protocolPair{
		clientPort: clientPort,
		serverPort: serverPort,
		targetPort: echo.port(),
		proxy:      proxy,
	}

	app, err := pair.dialTCP()
	require.NoError(t, err)
	defer app.Close()
	require.NoError(t, app.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, writeFull(app, []byte("before-server-restart")))
	requireReadExactly(t, app, []byte("before-server-restart"))

	require.NoError(t, server.Close())
	restartedAt := time.Now()
	startServerOnlyWithSession(t, extrojanType, serverPort, sessionOptions, []string{extrojanPassword})

	require.NoError(t, app.SetDeadline(time.Now().Add(2*time.Second)))
	oldPayload := []byte("old-session-must-fail")
	_, writeErr := app.Write(oldPayload)
	if writeErr == nil {
		reply := make([]byte, len(oldPayload))
		_, writeErr = io.ReadFull(app, reply)
	}
	require.Error(t, writeErr, "old TCP stream survived a server process restart")

	fresh, err := pair.dialTCP()
	require.NoError(t, err)
	defer fresh.Close()
	require.Less(t, time.Since(restartedAt), 4*time.Second, "fresh traffic waited for the five-second resume timeout")
	require.NoError(t, fresh.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, writeFull(fresh, []byte("after-server-restart")))
	requireReadExactly(t, fresh, []byte("after-server-restart"))
}

func TestExtrojanUDPReopensAfterServerRestartWithDefaultIdlePolicy(t *testing.T) {
	target := newUDPEchoTarget(t)
	serverPort := freeTCPPort(t)
	sessionOptions := map[string]any{
		"connections":             2,
		"resume_timeout":          "5s",
		"heartbeat_interval":      "50ms",
		"link_timeout":            "250ms",
		"reconnect_initial_delay": "20ms",
		"reconnect_max_delay":     "100ms",
	}
	server := startServerOnlyWithSession(t, extrojanType, serverPort, sessionOptions, []string{extrojanPassword})
	proxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))
	clientPort := freeTCPPort(t)
	startClientOnlyWithSession(t, extrojanType, clientPort, proxy.port(), sessionOptions, extrojanPassword)
	pair := &protocolPair{
		clientPort: clientPort,
		serverPort: serverPort,
		targetPort: target.port(),
		proxy:      proxy,
	}

	packetConn, err := pair.listenPacket()
	require.NoError(t, err)
	defer packetConn.Close()
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, udpRoundTrip(packetConn, target.addr(), []byte("before-server-restart")))

	require.NoError(t, server.Close())
	restartedAt := time.Now()
	startServerOnlyWithSession(t, extrojanType, serverPort, sessionOptions, []string{extrojanPassword})

	var recoveryErr error
	for time.Since(restartedAt) < 4*time.Second {
		require.NoError(t, packetConn.SetDeadline(time.Now().Add(500*time.Millisecond)))
		recoveryErr = udpRoundTrip(packetConn, target.addr(), []byte("after-server-restart"))
		if recoveryErr == nil {
			break
		}
	}
	require.NoError(t, recoveryErr, "application-facing UDP socket did not reopen before resume timeout")
	require.Less(t, time.Since(restartedAt), 4*time.Second, "UDP recovery waited for the five-second resume timeout")
}

func TestExtrojanUDPMultipleCarriersAndRecovery(t *testing.T) {
	target := newUDPEchoTarget(t)
	pair := newProtocolPair(t, extrojanType, extrojanType, target.port(), "2s", []string{extrojanPassword}, extrojanPassword)

	packetConn, err := pair.listenPacket()
	require.NoError(t, err)
	defer packetConn.Close()

	destination := target.addr()
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(12*time.Second)))
	for i := 0; i < 8; i++ {
		payload := []byte(fmt.Sprintf("warmup-%03d", i))
		require.NoError(t, udpRoundTrip(packetConn, destination, payload))
	}
	waitCondition(t, 3*time.Second, func() bool { return pair.proxy.activeCount() >= 2 }, "UDP association did not establish multiple TCP carriers")

	before := pair.proxy.byteSnapshot()
	for i := 0; i < 96; i++ {
		payload := append([]byte(fmt.Sprintf("striped-%03d|", i)), deterministicPayload(768, byte(i))...)
		require.NoError(t, udpRoundTrip(packetConn, destination, payload))
	}
	after := pair.proxy.byteSnapshot()
	require.GreaterOrEqual(t, carriersWithDelta(before, after, 4096), 2, "UDP payload was not distributed across at least two carriers")

	require.True(t, pair.proxy.closeOneActive(), "no carrier was available for single-carrier failure")
	for i := 0; i < 12; i++ {
		payload := []byte(fmt.Sprintf("after-one-carrier-%03d", i))
		require.NoError(t, udpRoundTrip(packetConn, destination, payload), "association closed when one carrier failed")
	}

	target.drainEvents()
	pair.proxy.beginOutage()
	floodStarted := time.Now()
	staleBody := deterministicPayload(1200, 0xa7)
	for i := 0; i < 4096; i++ {
		_ = packetConn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		payload := append([]byte(fmt.Sprintf("stale-during-outage-%04d|", i)), staleBody...)
		if _, writeErr := packetConn.WriteTo(payload, destination); writeErr != nil {
			break
		}
	}
	require.Less(t, time.Since(floodStarted), 3*time.Second, "full UDP queue deadlocked the association writer")
	time.Sleep(180 * time.Millisecond)
	pair.proxy.endOutage()
	waitCondition(t, 5*time.Second, func() bool { return pair.proxy.activeCount() >= 2 }, "UDP carriers did not recover")
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(8*time.Second)))
	require.NoError(t, udpRoundTripIgnoring(packetConn, destination, []byte("fresh-after-all-carriers"), "stale-during-outage-"))

	time.Sleep(250 * time.Millisecond)
	events := target.drainEvents()
	for _, event := range events {
		require.False(t, bytes.HasPrefix(event.data, []byte("stale-during-outage-")), "stale UDP datagram was replayed after recovery")
	}
	require.Len(t, target.sourceIdentities(), 1, "server changed target-side UDP source identity within one association")

}

func TestExtrojanUDPIdleCleanupAndLaneRotation(t *testing.T) {
	target := newUDPEchoTarget(t)
	tcpTarget := newTCPListenerAtPort(t, target.port())
	sessionOptions := map[string]any{
		"connections":             2,
		"resume_timeout":          "2s",
		"heartbeat_interval":      "50ms",
		"link_timeout":            "300ms",
		"retransmit_interval":     "50ms",
		"reconnect_initial_delay": "20ms",
		"reconnect_max_delay":     "100ms",
		"udp_idle_timeout":        "500ms",
		"lane_rotation_interval":  "150ms",
	}
	pair := newProtocolPairWithSession(t, extrojanType, extrojanType, target.port(), sessionOptions, []string{extrojanPassword}, extrojanPassword)

	packetConn, err := pair.listenPacket()
	require.NoError(t, err)
	defer packetConn.Close()
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, udpRoundTrip(packetConn, target.addr(), []byte("before-idle")))

	waitCondition(t, 2*time.Second, func() bool {
		return pair.proxy.acceptedCount() >= 3 && pair.proxy.activeCount() == 2
	}, "long UDP association did not rotate and refill one lane")
	waitCondition(t, 2*time.Second, func() bool {
		return pair.proxy.activeCount() == 0
	}, "idle UDP association did not release all TCP carriers")

	app, err := pair.dialTCP()
	require.NoError(t, err, "TCP dial raced with idle UDP session cleanup")
	peer := tcpTarget.accept(t, 5*time.Second)
	require.NoError(t, app.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, writeFull(app, []byte("tcp-after-udp-idle")))
	requireReadExactly(t, peer, []byte("tcp-after-udp-idle"))
	require.NoError(t, app.Close())
	require.NoError(t, peer.Close())

	require.NoError(t, packetConn.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, udpRoundTrip(packetConn, target.addr(), []byte("after-idle")), "UDP forwarding did not reopen after idle cleanup")
	waitCondition(t, 2*time.Second, func() bool {
		return pair.proxy.activeCount() == 2
	}, "UDP traffic after idle did not establish a new lane pool")
}

func TestExtrojanTrojanCompatibilityDowngrades(t *testing.T) {
	for _, tc := range []struct {
		name       string
		clientType string
		serverType string
	}{
		{name: "extrojan-client-to-trojan-server", clientType: extrojanType, serverType: "trojan"},
		{name: "trojan-client-to-extrojan-server", clientType: "trojan", serverType: extrojanType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tcpTarget := newTCPListener(t)
			pair := newProtocolPair(t, tc.clientType, tc.serverType, tcpTarget.port(), "1s", []string{extrojanPassword}, extrojanPassword)
			app, err := pair.dialTCP()
			require.NoError(t, err)
			peer := tcpTarget.accept(t, 5*time.Second)
			require.NoError(t, app.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, writeFull(app, []byte("legacy-tcp")))
			requireReadExactly(t, peer, []byte("legacy-tcp"))
			waitCondition(t, time.Second, func() bool { return pair.proxy.activeCount() == 1 }, "downgraded TCP did not use exactly one carrier")

			pair.proxy.beginOutage()
			var one [1]byte
			_, readErr := app.Read(one[:])
			require.Error(t, readErr, "downgraded TCP unexpectedly survived its carrier")
			pair.proxy.endOutage()
			require.NoError(t, app.Close())
			require.NoError(t, peer.Close())

			udpTarget := newUDPEchoTarget(t)
			udpPair := newProtocolPair(t, tc.clientType, tc.serverType, udpTarget.port(), "1s", []string{extrojanPassword}, extrojanPassword)
			pc, err := udpPair.listenPacket()
			require.NoError(t, err)
			defer pc.Close()
			require.NoError(t, pc.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, udpRoundTrip(pc, udpTarget.addr(), []byte("legacy-udp")))
			waitCondition(t, time.Second, func() bool { return udpPair.proxy.activeCount() == 1 }, "downgraded UDP did not use one TCP carrier")
		})
	}
}

func TestExtrojanWebSocketTransportCompatibility(t *testing.T) {
	for _, clientType := range []string{"trojan", extrojanType} {
		t.Run(clientType+"-client", func(t *testing.T) {
			target := newTCPListener(t)
			serverPort := freeTCPPort(t)
			sessionOptions := map[string]any{
				"connections":             3,
				"resume_timeout":          "2s",
				"heartbeat_interval":      "100ms",
				"link_timeout":            "500ms",
				"retransmit_interval":     "100ms",
				"reconnect_initial_delay": "50ms",
				"reconnect_max_delay":     "200ms",
				"max_unacked_bytes":       "64KB",
				"max_receive_bytes":       "64KB",
				"max_udp_queue_bytes":     "1MB",
				"max_udp_associations":    16,
				"max_sessions":            16,
				"max_sessions_per_user":   8,
			}
			transportOptions := map[string]any{
				"type": "ws",
				"path": "/extrojan-legacy-compat",
			}
			serverConfig := map[string]any{
				"inbounds": []any{
					map[string]any{
						"type":           extrojanType,
						"listen":         "127.0.0.1",
						"listen_port":    serverPort,
						"tcp_multi_path": true,
						"users": []any{
							map[string]any{"name": "legacy", "password": extrojanPassword},
						},
						"fallback": map[string]any{
							"server":      "127.0.0.1",
							"server_port": freeTCPPort(t),
						},
						"multiplex": map[string]any{"enabled": true},
						"transport": transportOptions,
						"session":   sessionOptions,
					},
				},
				"outbounds": []any{map[string]any{"type": "direct"}},
			}
			startSettledInstance(t, decodeOptions(t, serverConfig))

			proxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))
			clientPort := freeTCPPort(t)
			outbound := map[string]any{
				"type":        clientType,
				"server":      "127.0.0.1",
				"server_port": proxy.port(),
				"password":    extrojanPassword,
				"multiplex":   map[string]any{"enabled": true},
				"transport":   transportOptions,
			}
			if clientType == extrojanType {
				outbound["fallback_to_trojan"] = false
				outbound["session"] = sessionOptions
			}
			clientConfig := map[string]any{
				"inbounds": []any{
					map[string]any{
						"type":        "mixed",
						"listen":      "127.0.0.1",
						"listen_port": clientPort,
					},
				},
				"outbounds": []any{outbound},
			}
			startSettledInstance(t, decodeOptions(t, clientConfig))

			pair := &protocolPair{
				clientPort: clientPort,
				serverPort: serverPort,
				targetPort: target.port(),
				proxy:      proxy,
			}
			app, err := pair.dialTCP()
			require.NoError(t, err)
			defer app.Close()
			peer := target.accept(t, 5*time.Second)
			defer peer.Close()
			require.NoError(t, app.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, writeFull(app, []byte("websocket-compatible")))
			requireReadExactly(t, peer, []byte("websocket-compatible"))
			require.NoError(t, writeFull(peer, []byte("response")))
			requireReadExactly(t, app, []byte("response"))
		})
	}
}

func TestExtrojanTLSAndWebSocketRestartRecovery(t *testing.T) {
	for _, variant := range []struct {
		name      string
		websocket bool
	}{
		{name: "tls"},
		{name: "tls-websocket", websocket: true},
	} {
		t.Run(variant.name, func(t *testing.T) {
			caPEM, certificatePEM, keyPEM := createSelfSignedCertificate(t, "example.org")
			tcpTarget := newTCPEchoTarget(t)
			udpTarget := newUDPEchoTarget(t)
			serverPort := freeTCPPort(t)
			sessionOptions := map[string]any{
				"connections":             2,
				"resume_timeout":          "5s",
				"heartbeat_interval":      "50ms",
				"link_timeout":            "250ms",
				"reconnect_initial_delay": "20ms",
				"reconnect_max_delay":     "100ms",
			}

			var serverTransport map[string]any
			var clientTransport map[string]any
			if variant.websocket {
				serverTransport = map[string]any{
					"type": "ws",
					"path": "/extrojan-tls-restart",
				}
				clientTransport = map[string]any{
					"type": "ws",
					"path": "/extrojan-tls-restart",
					"headers": map[string]any{
						"Host": "example.org",
					},
				}
			}

			startTLSServer := func() *box.Box {
				inbound := map[string]any{
					"type":           extrojanType,
					"listen":         "127.0.0.1",
					"listen_port":    serverPort,
					"tcp_multi_path": true,
					"users": []any{
						map[string]any{"name": "tls-user", "password": extrojanPassword},
					},
					"tls": map[string]any{
						"enabled":          true,
						"server_name":      "example.org",
						"certificate_path": certificatePEM,
						"key_path":         keyPEM,
					},
					"session": sessionOptions,
				}
				if serverTransport != nil {
					inbound["transport"] = serverTransport
				}
				return startSettledInstance(t, decodeOptions(t, map[string]any{
					"inbounds":  []any{inbound},
					"outbounds": []any{map[string]any{"type": "direct"}},
				}))
			}

			server := startTLSServer()
			proxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))
			clientPort := freeTCPPort(t)
			outbound := map[string]any{
				"type":               extrojanType,
				"server":             "127.0.0.1",
				"server_port":        proxy.port(),
				"password":           extrojanPassword,
				"fallback_to_trojan": false,
				"tls": map[string]any{
					"enabled":          true,
					"server_name":      "example.org",
					"certificate_path": caPEM,
				},
				"session": sessionOptions,
			}
			if clientTransport != nil {
				outbound["transport"] = clientTransport
			}
			startSettledInstance(t, decodeOptions(t, map[string]any{
				"inbounds": []any{
					map[string]any{
						"type":        "mixed",
						"listen":      "127.0.0.1",
						"listen_port": clientPort,
					},
				},
				"outbounds": []any{outbound},
			}))

			tcpPair := &protocolPair{
				clientPort: clientPort,
				serverPort: serverPort,
				targetPort: tcpTarget.port(),
				proxy:      proxy,
			}
			app, err := tcpPair.dialTCP()
			require.NoError(t, err)
			defer app.Close()
			require.NoError(t, app.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, writeFull(app, []byte("tls-before-server-restart")))
			requireReadExactly(t, app, []byte("tls-before-server-restart"))

			firstCarrierBytes := proxy.firstClientBytesAfter(nil)
			require.GreaterOrEqual(t, len(firstCarrierBytes), 3, "TLS carrier did not produce a record header")
			require.Equal(t, []byte{0x16, 0x03}, firstCarrierBytes[:2], "carrier did not start with a TLS handshake record")

			udpPair := *tcpPair
			udpPair.targetPort = udpTarget.port()
			packetConn, err := udpPair.listenPacket()
			require.NoError(t, err)
			defer packetConn.Close()
			require.NoError(t, packetConn.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, udpRoundTrip(packetConn, udpTarget.addr(), []byte("tls-udp-before-server-restart")))

			require.NoError(t, server.Close())
			restartedAt := time.Now()
			startTLSServer()

			require.NoError(t, app.SetDeadline(time.Now().Add(2*time.Second)))
			oldPayload := []byte("tls-old-session-must-fail")
			_, oldStreamErr := app.Write(oldPayload)
			if oldStreamErr == nil {
				reply := make([]byte, len(oldPayload))
				_, oldStreamErr = io.ReadFull(app, reply)
			}
			require.Error(t, oldStreamErr, "old TLS TCP stream survived a server process restart")

			fresh, err := tcpPair.dialTCP()
			require.NoError(t, err)
			defer fresh.Close()
			require.Less(t, time.Since(restartedAt), 4*time.Second, "fresh TLS traffic waited for the five-second resume timeout")
			require.NoError(t, fresh.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, writeFull(fresh, []byte("tls-after-server-restart")))
			requireReadExactly(t, fresh, []byte("tls-after-server-restart"))

			var recoveryErr error
			for time.Since(restartedAt) < 4*time.Second {
				require.NoError(t, packetConn.SetDeadline(time.Now().Add(500*time.Millisecond)))
				recoveryErr = udpRoundTrip(packetConn, udpTarget.addr(), []byte("tls-udp-after-server-restart"))
				if recoveryErr == nil {
					break
				}
			}
			require.NoError(t, recoveryErr, "TLS UDP association did not reopen before resume timeout")
			require.Less(t, time.Since(restartedAt), 4*time.Second, "TLS UDP recovery waited for the five-second resume timeout")
		})
	}
}

func TestExtrojanRejectsInvalidAuthenticationAndNegotiation(t *testing.T) {
	t.Run("wrong-user", func(t *testing.T) {
		target := newTCPListener(t)
		pair := newProtocolPair(t, extrojanType, extrojanType, target.port(), "1s", []string{extrojanPassword}, "wrong-password")
		app, err := pair.dialTCP()
		if err == nil {
			_ = app.SetDeadline(time.Now().Add(time.Second))
			_, err = app.Write([]byte("must-not-arrive"))
			if err == nil {
				var one [1]byte
				_, err = app.Read(one[:])
			}
			_ = app.Close()
		}
		require.Error(t, err)
		target.requireNoConnection(t, 200*time.Millisecond)
	})

	t.Run("forged-and-cross-user-resume", func(t *testing.T) {
		targetA := newTCPListener(t)
		pairA := newProtocolPair(t, extrojanType, extrojanType, targetA.port(), "2s", []string{"user-a-password", "user-b-password"}, "user-a-password")
		app, err := pairA.dialTCP()
		require.NoError(t, err)
		defer app.Close()
		peer := targetA.accept(t, 5*time.Second)
		defer peer.Close()
		require.NoError(t, writeFull(app, []byte("establish")))
		requireReadExactly(t, peer, []byte("establish"))

		oldIDs := pairA.proxy.connectionIDs()
		pairA.proxy.beginOutage()
		time.Sleep(120 * time.Millisecond)
		pairA.proxy.endOutage()
		require.NoError(t, writeFull(app, []byte("resumed")))
		requireReadExactly(t, peer, []byte("resumed"))
		resumeBytes := pairA.proxy.firstClientBytesAfter(oldIDs)
		require.NotEmpty(t, resumeBytes, "could not observe a public resume handshake")

		forgedToken := append([]byte(nil), resumeBytes...)
		tokenOffset := 56 + 2 + 1 + 1 + 16
		require.Greater(t, len(forgedToken), tokenOffset)
		forgedToken[tokenOffset] ^= 0x80
		requireRawRejected(t, pairA.serverPort, forgedToken, targetA)

		crossUser := append([]byte(nil), resumeBytes...)
		userBHash := sha256.Sum224([]byte("user-b-password"))
		copy(crossUser[:56], []byte(hex.EncodeToString(userBHash[:])))
		requireRawRejected(t, pairA.serverPort, crossUser, targetA)

		require.NoError(t, writeFull(app, []byte("still-alive")))
		requireReadExactly(t, peer, []byte("still-alive"))
	})

	t.Run("unknown-version", func(t *testing.T) {
		target := newTCPListener(t)
		serverPort := freeTCPPort(t)
		startServerOnly(t, extrojanType, serverPort, "1s", []string{extrojanPassword})

		hash := sha256.Sum224([]byte(extrojanPassword))
		hello := append([]byte(hex.EncodeToString(hash[:])+"\r\n"), 0xe1, 0xff, 0, 0, 0, 1)
		requireRawRejected(t, serverPort, hello, target)
	})

	t.Run("slow-auth-prefix", func(t *testing.T) {
		target := newTCPListener(t)
		serverPort := freeTCPPort(t)
		startServerOnlyWithSession(t, extrojanType, serverPort, map[string]any{
			"resume_timeout":     "1s",
			"heartbeat_interval": "50ms",
			"link_timeout":       "200ms",
		}, []string{extrojanPassword})
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), time.Second)
		require.NoError(t, err)
		defer conn.Close()
		require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
		require.NoError(t, writeFull(conn, []byte("partial")))
		var one [1]byte
		_, err = conn.Read(one[:])
		require.Error(t, err)
		require.False(t, errors.Is(err, os.ErrDeadlineExceeded), "partial auth prefix occupied the connection past link_timeout")
		target.requireNoConnection(t, 200*time.Millisecond)
	})
}

func TestExtrojanBackpressureBoundsUnconfirmedData(t *testing.T) {
	target := newTCPListener(t)
	pair := newProtocolPair(t, extrojanType, extrojanType, target.port(), "2s", []string{extrojanPassword}, extrojanPassword)
	app, err := pair.dialTCP()
	require.NoError(t, err)
	defer app.Close()
	peer := target.accept(t, 5*time.Second)
	defer peer.Close()

	require.NoError(t, writeFull(app, []byte("ready")))
	requireReadExactly(t, peer, []byte("ready"))
	pair.proxy.beginOutage()
	require.NoError(t, app.SetWriteDeadline(time.Now().Add(750*time.Millisecond)))

	chunk := deterministicPayload(1024*1024, 0x55)
	var accepted int64
	for accepted <= 64*1024*1024 {
		n, writeErr := app.Write(chunk)
		accepted += int64(n)
		if writeErr != nil {
			break
		}
	}
	require.LessOrEqual(t, accepted, int64(64*1024*1024), "unconfirmed stream data grew without bounded backpressure")

	pair.proxy.endOutage()
	require.NoError(t, app.SetWriteDeadline(time.Time{}))
	require.NoError(t, app.SetReadDeadline(time.Now().Add(3*time.Second)))
}

func TestExtrojanConcurrentResumeAndClose(t *testing.T) {
	if testing.Short() {
		t.Skip("concurrent recovery stress test")
	}
	echo := newTCPEchoTarget(t)
	pair := newProtocolPair(t, extrojanType, extrojanType, echo.port(), "2s", []string{extrojanPassword}, extrojanPassword)

	const workers = 24
	start := make(chan struct{})
	faultsDone := make(chan struct{})
	ready := make(chan error, workers)
	errCh := make(chan error, workers)
	var workerWG sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		workerWG.Add(1)
		go func(worker int) {
			defer workerWG.Done()
			conn, err := pair.dialTCP()
			if err != nil {
				ready <- fmt.Errorf("worker %d dial: %w", worker, err)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			message := []byte(fmt.Sprintf("%03d:ready|", worker))
			if err = writeFull(conn, message); err != nil {
				ready <- fmt.Errorf("worker %d readiness write: %w", worker, err)
				return
			}
			reply := make([]byte, len(message))
			if _, err = io.ReadFull(conn, reply); err != nil {
				ready <- fmt.Errorf("worker %d readiness read: %w", worker, err)
				return
			}
			if !bytes.Equal(message, reply) {
				ready <- fmt.Errorf("worker %d readiness echo mismatch", worker)
				return
			}
			ready <- nil
			<-start
			for sequence := 0; ; sequence++ {
				select {
				case <-faultsDone:
					errCh <- nil
					return
				default:
				}
				message = []byte(fmt.Sprintf("%03d:%03d|", worker, sequence))
				if err = writeFull(conn, message); err != nil {
					errCh <- fmt.Errorf("worker %d sequence %d write: %w", worker, sequence, err)
					return
				}
				reply := make([]byte, len(message))
				if _, err = io.ReadFull(conn, reply); err != nil {
					errCh <- fmt.Errorf("worker %d sequence %d read: %w", worker, sequence, err)
					return
				}
				if !bytes.Equal(message, reply) {
					errCh <- fmt.Errorf("worker %d sequence %d: echo mismatch", worker, sequence)
					return
				}
			}
		}(worker)
	}

	var readinessErrors []error
	for range workers {
		if err := <-ready; err != nil {
			readinessErrors = append(readinessErrors, err)
		}
	}
	close(start)
	for i := 0; i < 10; i++ {
		time.Sleep(35 * time.Millisecond)
		pair.proxy.beginOutage()
		time.Sleep(25 * time.Millisecond)
		pair.proxy.endOutage()
	}
	close(faultsDone)
	workerWG.Wait()
	for _, err := range readinessErrors {
		require.NoError(t, err)
	}
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
	require.Greater(t, pair.proxy.acceptedCount(), 1, "no replacement carrier was observed")
}

type protocolPair struct {
	clientPort uint16
	serverPort uint16
	targetPort uint16
	proxy      *tcpChaosProxy
}

func newProtocolPair(t *testing.T, clientType, serverType string, targetPort uint16, resumeTimeout string, users []string, password string) *protocolPair {
	return newProtocolPairWithSession(t, clientType, serverType, targetPort, map[string]any{"resume_timeout": resumeTimeout}, users, password)
}

func newProtocolPairWithSession(t *testing.T, clientType, serverType string, targetPort uint16, sessionOptions map[string]any, users []string, password string) *protocolPair {
	t.Helper()
	serverPort := freeTCPPort(t)
	startServerOnlyWithSession(t, serverType, serverPort, sessionOptions, users)
	proxy := newTCPChaosProxy(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))
	clientPort := freeTCPPort(t)
	startClientOnlyWithSession(t, clientType, clientPort, proxy.port(), sessionOptions, password)
	return &protocolPair{clientPort: clientPort, serverPort: serverPort, targetPort: targetPort, proxy: proxy}
}

func startServerOnly(t *testing.T, protocolType string, listenPort uint16, resumeTimeout string, users []string) {
	startServerOnlyWithSession(t, protocolType, listenPort, map[string]any{"resume_timeout": resumeTimeout}, users)
}

func startServerOnlyWithSession(t *testing.T, protocolType string, listenPort uint16, sessionOptions map[string]any, users []string) *box.Box {
	t.Helper()
	userObjects := make([]map[string]any, 0, len(users))
	for index, password := range users {
		userObjects = append(userObjects, map[string]any{"name": fmt.Sprintf("user-%d", index), "password": password})
	}
	inbound := map[string]any{
		"type":        protocolType,
		"listen":      "127.0.0.1",
		"listen_port": listenPort,
		"users":       userObjects,
	}
	if protocolType == extrojanType {
		inbound["session"] = sessionOptions
	}
	config := map[string]any{
		"inbounds": []any{inbound},
		"outbounds": []any{
			map[string]any{
				"type": "direct",
			},
		},
	}
	return startSettledInstance(t, decodeOptions(t, config))
}

func startClientOnly(t *testing.T, protocolType string, listenPort, serverPort uint16, resumeTimeout, password string) {
	startClientOnlyWithSession(t, protocolType, listenPort, serverPort, map[string]any{"resume_timeout": resumeTimeout}, password)
}

func startClientOnlyWithSession(t *testing.T, protocolType string, listenPort, serverPort uint16, sessionOptions map[string]any, password string) {
	t.Helper()
	outbound := map[string]any{
		"type":        protocolType,
		"server":      "127.0.0.1",
		"server_port": serverPort,
		"password":    password,
	}
	if protocolType == extrojanType {
		outbound["session"] = sessionOptions
	}
	config := map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"listen":      "127.0.0.1",
				"listen_port": listenPort,
			},
		},
		"outbounds": []any{outbound},
	}
	startSettledInstance(t, decodeOptions(t, config))
}

// startupNetworkSettle covers the interface update that sing-box dispatches
// shortly after an instance starts. That update resets the network, which
// closes tracked connections and resets multiplex clients, so a scenario that
// starts an instance and immediately pushes traffic through it can lose its
// first connection for reasons unrelated to the protocol under test. It is a
// property of instance startup, not of extrojan: plain Trojan over WebSocket
// with multiplex loses its connection the same way.
const startupNetworkSettle = 750 * time.Millisecond

func startSettledInstance(t *testing.T, options option.Options) *box.Box {
	t.Helper()
	instance := startInstance(t, options)
	time.Sleep(startupNetworkSettle)
	return instance
}

func decodeOptions(t *testing.T, config map[string]any) option.Options {
	t.Helper()
	content, err := stdjson.Marshal(config)
	require.NoError(t, err)
	var options option.Options
	require.NoError(t, singjson.UnmarshalContext(globalCtx, content, &options))
	return options
}

func (p *protocolPair) dialTCP() (net.Conn, error) {
	return p.dialTCPWithTimeout(5 * time.Second)
}

func (p *protocolPair) dialTCPWithTimeout(timeout time.Duration) (net.Conn, error) {
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", p.clientPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", p.targetPort))
}

func (p *protocolPair) listenPacket() (net.PacketConn, error) {
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", p.clientPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return dialer.ListenPacket(ctx, M.ParseSocksaddrHostPort("127.0.0.1", p.targetPort))
}

type proxyByteCount struct {
	toServer   int64
	fromServer int64
}

type proxyPair struct {
	id       int
	client   net.Conn
	server   net.Conn
	proxy    *tcpChaosProxy
	closeOne sync.Once
	finished atomic.Int32
}

// finishDirection records one exhausted copy direction. The pair is torn down
// only once both directions have ended, so a peer that half-closes keeps
// receiving on the other direction. Collapsing the pair on the first EOF would
// break any protocol that relies on half-close, such as the multiplexed legacy
// Trojan path, which is a limitation of this forwarder and not of the code
// under test.
func (p *proxyPair) finishDirection() {
	if p.finished.Add(1) == 2 {
		p.close()
	}
}

func (p *proxyPair) close() {
	p.closeOne.Do(func() {
		_ = p.client.Close()
		_ = p.server.Close()
		p.proxy.mu.Lock()
		delete(p.proxy.active, p.id)
		p.proxy.mu.Unlock()
	})
}

type tcpChaosProxy struct {
	listener net.Listener
	upstream string
	mu       sync.Mutex
	outage   bool
	closed   bool
	nextID   int
	accepted int
	peak     int
	active   map[int]*proxyPair
	bytes    map[int]proxyByteCount
	first    map[int][]byte
	wg       sync.WaitGroup
}

func newTCPChaosProxy(t *testing.T, upstream string) *tcpChaosProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	proxy := &tcpChaosProxy{
		listener: listener,
		upstream: upstream,
		active:   make(map[int]*proxyPair),
		bytes:    make(map[int]proxyByteCount),
		first:    make(map[int][]byte),
	}
	proxy.wg.Add(1)
	go proxy.acceptLoop()
	t.Cleanup(proxy.close)
	return proxy
}

func (p *tcpChaosProxy) port() uint16 {
	return uint16(p.listener.Addr().(*net.TCPAddr).Port)
}

func (p *tcpChaosProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.nextID++
		id := p.nextID
		p.accepted++
		blocked := p.outage || p.closed
		p.mu.Unlock()
		if blocked {
			_ = client.Close()
			continue
		}
		server, err := net.DialTimeout("tcp", p.upstream, 2*time.Second)
		if err != nil {
			_ = client.Close()
			continue
		}
		pair := &proxyPair{id: id, client: client, server: server, proxy: p}
		p.mu.Lock()
		if p.outage || p.closed {
			p.mu.Unlock()
			pair.close()
			continue
		}
		p.active[id] = pair
		if len(p.active) > p.peak {
			p.peak = len(p.active)
		}
		p.bytes[id] = proxyByteCount{}
		p.mu.Unlock()
		p.wg.Add(2)
		go p.copy(pair, server, client, true)
		go p.copy(pair, client, server, false)
	}
}

func (p *tcpChaosProxy) copy(pair *proxyPair, destination, source net.Conn, toServer bool) {
	defer p.wg.Done()
	buffer := make([]byte, 32*1024)
	for {
		n, readErr := source.Read(buffer)
		if n > 0 {
			p.mu.Lock()
			count := p.bytes[pair.id]
			if toServer {
				count.toServer += int64(n)
				if len(p.first[pair.id]) < 64*1024 {
					remaining := 64*1024 - len(p.first[pair.id])
					capture := n
					if capture > remaining {
						capture = remaining
					}
					p.first[pair.id] = append(p.first[pair.id], buffer[:capture]...)
				}
			} else {
				count.fromServer += int64(n)
			}
			p.bytes[pair.id] = count
			p.mu.Unlock()
			if writeErr := writeFull(destination, buffer[:n]); writeErr != nil {
				pair.close()
				return
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if closer, loaded := destination.(interface{ CloseWrite() error }); loaded {
					_ = closer.CloseWrite()
					pair.finishDirection()
					return
				}
			}
			pair.close()
			return
		}
	}
}

func (p *tcpChaosProxy) beginOutage() {
	p.mu.Lock()
	p.outage = true
	pairs := make([]*proxyPair, 0, len(p.active))
	for _, pair := range p.active {
		pairs = append(pairs, pair)
	}
	p.mu.Unlock()
	for _, pair := range pairs {
		pair.close()
	}
}

func (p *tcpChaosProxy) endOutage() {
	p.mu.Lock()
	p.outage = false
	p.mu.Unlock()
}

func (p *tcpChaosProxy) closeOneActive() bool {
	p.mu.Lock()
	var selected *proxyPair
	for _, pair := range p.active {
		selected = pair
		break
	}
	p.mu.Unlock()
	if selected == nil {
		return false
	}
	selected.close()
	return true
}

func (p *tcpChaosProxy) activeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.active)
}

func (p *tcpChaosProxy) acceptedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted
}

func (p *tcpChaosProxy) peakActiveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

func (p *tcpChaosProxy) byteSnapshot() map[int]proxyByteCount {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make(map[int]proxyByteCount, len(p.bytes))
	for id, count := range p.bytes {
		result[id] = count
	}
	return result
}

func (p *tcpChaosProxy) connectionIDs() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]int, 0, len(p.first))
	for id := range p.first {
		result = append(result, id)
	}
	sort.Ints(result)
	return result
}

func (p *tcpChaosProxy) firstClientBytesAfter(previous []int) []byte {
	seen := make(map[int]bool, len(previous))
	for _, id := range previous {
		seen[id] = true
	}
	waitUntil := time.Now().Add(2 * time.Second)
	for time.Now().Before(waitUntil) {
		p.mu.Lock()
		var candidate []byte
		for id, data := range p.first {
			if !seen[id] && len(data) > len(candidate) {
				candidate = append(candidate[:0], data...)
			}
		}
		p.mu.Unlock()
		if len(candidate) > 0 {
			return candidate
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func (p *tcpChaosProxy) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	pairs := make([]*proxyPair, 0, len(p.active))
	for _, pair := range p.active {
		pairs = append(pairs, pair)
	}
	p.mu.Unlock()
	_ = p.listener.Close()
	for _, pair := range pairs {
		pair.close()
	}
	p.wg.Wait()
}

type tcpListener struct {
	listener net.Listener
	mu       sync.Mutex
	accepted int
}

func newTCPListener(t *testing.T) *tcpListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	target := &tcpListener{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	return target
}

func newTCPListenerAtPort(t *testing.T, port uint16) *tcpListener {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	require.NoError(t, err)
	target := &tcpListener{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	return target
}

func (t *tcpListener) port() uint16 {
	return uint16(t.listener.Addr().(*net.TCPAddr).Port)
}

func (t *tcpListener) accept(testingT *testing.T, timeout time.Duration) net.Conn {
	testingT.Helper()
	result := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := t.listener.Accept()
		if err == nil {
			t.mu.Lock()
			t.accepted++
			t.mu.Unlock()
		}
		result <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: err}
	}()
	select {
	case accepted := <-result:
		require.NoError(testingT, accepted.err)
		return accepted.conn
	case <-time.After(timeout):
		testingT.Fatal("target did not receive a TCP connection")
		return nil
	}
}

func (t *tcpListener) acceptedCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.accepted
}

func (t *tcpListener) requireNoConnection(testingT *testing.T, timeout time.Duration) {
	testingT.Helper()
	tcpListener, loaded := t.listener.(*net.TCPListener)
	require.True(testingT, loaded)
	require.NoError(testingT, tcpListener.SetDeadline(time.Now().Add(timeout)))
	conn, err := tcpListener.Accept()
	if err == nil {
		_ = conn.Close()
		testingT.Fatal("rejected handshake reached the target")
	}
	var netError net.Error
	require.ErrorAs(testingT, err, &netError)
	require.True(testingT, netError.Timeout(), "target accept failed for an unexpected reason")
	require.NoError(testingT, tcpListener.SetDeadline(time.Time{}))
}

type tcpEchoTarget struct {
	listener net.Listener
	wg       sync.WaitGroup
}

func newTCPEchoTarget(t *testing.T) *tcpEchoTarget {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	target := &tcpEchoTarget{listener: listener}
	target.wg.Add(1)
	go func() {
		defer target.wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			target.wg.Add(1)
			go func() {
				defer target.wg.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		target.wg.Wait()
	})
	return target
}

func (t *tcpEchoTarget) port() uint16 {
	return uint16(t.listener.Addr().(*net.TCPAddr).Port)
}

type udpEvent struct {
	data   []byte
	source string
}

type udpEchoTarget struct {
	conn    *net.UDPConn
	events  chan udpEvent
	mu      sync.Mutex
	sources map[string]bool
	wg      sync.WaitGroup
}

func newUDPEchoTarget(t *testing.T) *udpEchoTarget {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	target := &udpEchoTarget{
		conn:    conn,
		events:  make(chan udpEvent, 32768),
		sources: make(map[string]bool),
	}
	target.wg.Add(1)
	go func() {
		defer target.wg.Done()
		buffer := make([]byte, 64*1024)
		for {
			n, source, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			data := append([]byte(nil), buffer[:n]...)
			target.mu.Lock()
			target.sources[source.String()] = true
			target.mu.Unlock()
			select {
			case target.events <- udpEvent{data: data, source: source.String()}:
			default:
			}
			_, _ = conn.WriteToUDP(data, source)
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		target.wg.Wait()
	})
	return target
}

func (t *udpEchoTarget) port() uint16 {
	return uint16(t.conn.LocalAddr().(*net.UDPAddr).Port)
}

func (t *udpEchoTarget) addr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(t.port())}
}

func (t *udpEchoTarget) drainEvents() []udpEvent {
	var result []udpEvent
	for {
		select {
		case event := <-t.events:
			result = append(result, event)
		default:
			return result
		}
	}
}

func (t *udpEchoTarget) sourceIdentities() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]string, 0, len(t.sources))
	for source := range t.sources {
		result = append(result, source)
	}
	sort.Strings(result)
	return result
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())
	return port
}

func deterministicPayload(size int, seed byte) []byte {
	payload := make([]byte, size)
	state := uint32(seed) + 1
	for index := range payload {
		state = state*1664525 + 1013904223
		payload[index] = byte(state >> 24)
	}
	return payload
}

func writeChunked(conn net.Conn, payload []byte, chunkSize int, pause time.Duration) error {
	for offset := 0; offset < len(payload); {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		if err := writeFull(conn, payload[offset:end]); err != nil {
			return err
		}
		offset = end
		if pause > 0 {
			time.Sleep(pause)
		}
	}
	return nil
}

func writeFull(writer io.Writer, content []byte) error {
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

func closeWrite(conn net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if halfCloser, loaded := conn.(closeWriter); loaded {
		return halfCloser.CloseWrite()
	}
	return fmt.Errorf("%T does not expose CloseWrite", conn)
}

func readAllCounting(reader io.Reader, counter *atomic.Int64) ([]byte, error) {
	var output bytes.Buffer
	buffer := make([]byte, 4096)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			counter.Add(int64(n))
			_, _ = output.Write(buffer[:n])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return output.Bytes(), nil
			}
			return output.Bytes(), err
		}
	}
}

func requireReadExactly(t *testing.T, reader io.Reader, expected []byte) {
	t.Helper()
	actual := make([]byte, len(expected))
	_, err := io.ReadFull(reader, actual)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func waitAtomicAtLeast(t *testing.T, value *atomic.Int64, minimum int64, timeout time.Duration) {
	t.Helper()
	waitCondition(t, timeout, func() bool { return value.Load() >= minimum }, fmt.Sprintf("stream did not reach byte boundary %d", minimum))
}

func waitCondition(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, condition(), message)
}

func carriersWithDelta(before, after map[int]proxyByteCount, minimum int64) int {
	count := 0
	for id, current := range after {
		if current.toServer-before[id].toServer >= minimum {
			count++
		}
	}
	return count
}

func udpRoundTrip(conn net.PacketConn, destination net.Addr, payload []byte) error {
	return udpRoundTripIgnoring(conn, destination, payload, "")
}

func udpRoundTripIgnoring(conn net.PacketConn, destination net.Addr, payload []byte, ignoredPrefix string) error {
	if _, err := conn.WriteTo(payload, destination); err != nil {
		return err
	}
	buffer := make([]byte, 64*1024)
	for {
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if ignoredPrefix != "" && bytes.HasPrefix(buffer[:n], []byte(ignoredPrefix)) {
			continue
		}
		if !bytes.Equal(buffer[:n], payload) {
			return fmt.Errorf("UDP echo mismatch: got %q, want %q", buffer[:n], payload)
		}
		return nil
	}
}

func requireRawRejected(t *testing.T, serverPort uint16, content []byte, target *tcpListener) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	_, writeErr := conn.Write(content)
	if writeErr == nil {
		var response [256]byte
		for writeErr == nil {
			_, writeErr = conn.Read(response[:])
		}
	}
	require.Error(t, writeErr, "malformed or foreign resume handshake was not rejected")
	require.False(t, errors.Is(writeErr, os.ErrDeadlineExceeded), "rejection did not close the connection")
	target.requireNoConnection(t, 200*time.Millisecond)
}
