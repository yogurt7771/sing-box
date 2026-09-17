package exanytls

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	ext "github.com/sagernet/sing-box/transport/extrojan"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestSessionConnectionDefaultAndOverride(t *testing.T) {
	defaultConfig, err := buildSessionConfig(option.ExtrojanSessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if defaultConfig.Connections != 1 {
		t.Fatalf("default physical connection count is %d, want 1", defaultConfig.Connections)
	}
	anyTLSOptions := buildAnyTLSSessionOptions(defaultConfig)
	recoveryBudget := defaultConfig.RecoveryBudget()
	if anyTLSOptions.ControlWriteTimeout != recoveryBudget || anyTLSOptions.StreamOpenTimeout != recoveryBudget {
		t.Fatalf("AnyTLS timeouts do not cover the recovery budget %s: %+v", recoveryBudget, anyTLSOptions)
	}
	// Both budgets abort the whole AnyTLS session, so they have to outlast the
	// bare detection plus resume window rather than expire exactly with it.
	if recoveryBudget <= defaultConfig.LinkTimeout+defaultConfig.ResumeTimeout {
		t.Fatalf("recovery budget %s leaves no margin over link+resume", recoveryBudget)
	}
	overriddenConfig, err := buildSessionConfig(option.ExtrojanSessionOptions{Connections: 3})
	if err != nil {
		t.Fatal(err)
	}
	if overriddenConfig.Connections != 3 {
		t.Fatalf("configured physical connection count is %d, want 3", overriddenConfig.Connections)
	}
}

func TestOutboundOptionsInheritCompleteAnyTLSConfiguration(t *testing.T) {
	var options option.ExAnyTLSOutboundOptions
	err := singjson.Unmarshal([]byte(`{
		"server": "example.org",
		"server_port": 443,
		"password": "secret",
		"idle_session_check_interval": "7s",
		"idle_session_timeout": "11s",
		"min_idle_session": 5,
		"client_metadata": "client-name",
		"session": { "connections": 2 }
	}`), &options)
	if err != nil {
		t.Fatal(err)
	}
	if options.IdleSessionCheckInterval.Build() != 7*time.Second {
		t.Fatalf("idle_session_check_interval = %s, want 7s", options.IdleSessionCheckInterval.Build())
	}
	if options.IdleSessionTimeout.Build() != 11*time.Second {
		t.Fatalf("idle_session_timeout = %s, want 11s", options.IdleSessionTimeout.Build())
	}
	if options.MinIdleSession != 5 {
		t.Fatalf("min_idle_session = %d, want 5", options.MinIdleSession)
	}
	if options.ClientMetadata != "client-name" {
		t.Fatalf("client_metadata = %q, want client-name", options.ClientMetadata)
	}
	if options.Session.Connections != 2 {
		t.Fatalf("session.connections = %d, want 2", options.Session.Connections)
	}
}

type negotiatedConn struct {
	net.Conn
	config ext.Config
}

func (c negotiatedConn) SessionConfig() ext.Config { return c.config }

// The server decides the resume window during the handshake, so a session whose
// budgets were sized from the local configuration would give up while the
// carrier is still recoverable.
func TestSessionOptionsFollowNegotiatedRecoveryWindow(t *testing.T) {
	localConfig, err := buildSessionConfig(option.ExtrojanSessionOptions{ResumeTimeout: badoption.Duration(10 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	instance := &Outbound{clientMetadata: "client-name"}

	negotiatedConfig := localConfig
	negotiatedConfig.ResumeTimeout = 120 * time.Second
	resumable := instance.sessionOptionsFor(negotiatedConn{config: negotiatedConfig})
	if want := negotiatedConfig.RecoveryBudget(); resumable.ControlWriteTimeout != want {
		t.Fatalf("control write timeout = %s, want the negotiated budget %s", resumable.ControlWriteTimeout, want)
	}
	if resumable.ControlWriteTimeout <= localConfig.RecoveryBudget() {
		t.Fatal("session budget still follows the local configuration instead of the negotiated one")
	}
	if resumable.ClientMetadata != "client-name" {
		t.Fatalf("client_metadata = %q, want client-name", resumable.ClientMetadata)
	}

	// A compatible AnyTLS carrier cannot recover, so it keeps the upstream
	// defaults instead of an inflated budget that only delays reporting a dead
	// connection.
	legacy := instance.sessionOptionsFor(new(net.TCPConn))
	if legacy.ControlWriteTimeout != 0 || legacy.StreamOpenTimeout != 0 {
		t.Fatalf("compatible AnyTLS carrier inherited a recovery budget: %+v", legacy)
	}
	if legacy.ClientMetadata != "client-name" {
		t.Fatalf("client_metadata = %q, want client-name", legacy.ClientMetadata)
	}
}
