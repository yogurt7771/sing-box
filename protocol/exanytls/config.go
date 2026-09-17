package exanytls

import (
	"time"

	"github.com/sagernet/sing-box/option"
	anySession "github.com/sagernet/sing-box/protocol/exanytls/session"
	extrojanProtocol "github.com/sagernet/sing-box/protocol/extrojan"
	ext "github.com/sagernet/sing-box/transport/extrojan"
)

func buildSessionConfig(options option.ExtrojanSessionOptions) (ext.Config, error) {
	config, err := extrojanProtocol.BuildSessionConfig(options)
	if err != nil {
		return ext.Config{}, err
	}
	if options.Connections == 0 {
		// ExAnyTLS is intended for connection-limited relays. One replaceable
		// carrier is therefore the safe default; users may opt into more lanes.
		config.Connections = 1
	}
	return config, nil
}

// buildAnyTLSSessionOptions widens the AnyTLS failure budgets to the carrier's
// recovery window. Both the control-write deadline and the SYNACK watchdog
// abort the whole AnyTLS session, so leaving them at the upstream defaults
// would tear down a session that the carrier is still able to resume. The
// budget matches the one the extrojan mux uses, including its margin for
// reconnect backoff and retransmission, so neither layer gives up first.
func buildAnyTLSSessionOptions(config ext.Config) anySession.Options {
	recoveryBudget := config.RecoveryBudget()
	controlWriteTimeout := recoveryBudget
	if controlWriteTimeout < 5*time.Second {
		controlWriteTimeout = 5 * time.Second
	}
	streamOpenTimeout := recoveryBudget
	if streamOpenTimeout < 3*time.Second {
		streamOpenTimeout = 3 * time.Second
	}
	return anySession.Options{
		ControlWriteTimeout: controlWriteTimeout,
		StreamOpenTimeout:   streamOpenTimeout,
	}
}
