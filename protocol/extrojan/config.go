package extrojan

import (
	"fmt"
	"math"
	"time"

	"github.com/sagernet/sing-box/option"
	ext "github.com/sagernet/sing-box/transport/extrojan"
)

// BuildSessionConfig converts the shared resumable-session JSON options into
// the transport configuration used by extrojan and exanytls.
func BuildSessionConfig(options option.ExtrojanSessionOptions) (ext.Config, error) {
	config := ext.DefaultConfig()
	if options.Connections != 0 {
		config.Connections = options.Connections
	}
	if options.ResumeTimeout != 0 {
		config.ResumeTimeout = time.Duration(options.ResumeTimeout)
	}
	if options.HeartbeatInterval != 0 {
		config.HeartbeatInterval = time.Duration(options.HeartbeatInterval)
	}
	if options.LinkTimeout != 0 {
		config.LinkTimeout = time.Duration(options.LinkTimeout)
	}
	if options.RetransmitInterval != 0 {
		config.RetransmitInterval = time.Duration(options.RetransmitInterval)
	}
	if options.MaxUnackedBytes != nil {
		if options.MaxUnackedBytes.Value() > math.MaxInt {
			return ext.Config{}, fmt.Errorf("max_unacked_bytes exceeds platform limit")
		}
		config.MaxUnackedBytes = int(options.MaxUnackedBytes.Value())
	}
	if options.MaxReceiveBytes != nil {
		if options.MaxReceiveBytes.Value() > math.MaxInt {
			return ext.Config{}, fmt.Errorf("max_receive_bytes exceeds platform limit")
		}
		config.MaxReceiveBytes = int(options.MaxReceiveBytes.Value())
	}
	if options.MaxStreamSegments != 0 {
		config.MaxStreamSegments = options.MaxStreamSegments
	}
	if options.LaneQueueSize != 0 {
		config.LaneQueueSize = options.LaneQueueSize
	}
	if options.UDPQueueSize != 0 {
		config.UDPQueueSize = options.UDPQueueSize
	}
	if options.MaxUDPQueueBytes != nil {
		if options.MaxUDPQueueBytes.Value() > math.MaxInt {
			return ext.Config{}, fmt.Errorf("max_udp_queue_bytes exceeds platform limit")
		}
		config.MaxUDPQueueBytes = int(options.MaxUDPQueueBytes.Value())
	}
	if options.MaxUDPAssociations != 0 {
		config.MaxUDPAssociations = options.MaxUDPAssociations
	}
	if options.UDPIdleTimeout != 0 {
		config.UDPIdleTimeout = time.Duration(options.UDPIdleTimeout)
	}
	if options.LaneRotationInterval != 0 {
		config.LaneRotationInterval = time.Duration(options.LaneRotationInterval)
	}
	if options.MaxSessions != 0 {
		config.MaxSessions = options.MaxSessions
		if options.MaxSessionsPerUser == 0 && config.MaxSessionsPerUser > config.MaxSessions {
			config.MaxSessionsPerUser = config.MaxSessions
		}
	}
	if options.MaxSessionsPerUser != 0 {
		config.MaxSessionsPerUser = options.MaxSessionsPerUser
	}
	if options.LegacyProbeTimeout != 0 {
		config.LegacyProbeTimeout = time.Duration(options.LegacyProbeTimeout)
	}
	if options.ReconnectInitialDelay != 0 {
		config.ReconnectInitialDelay = time.Duration(options.ReconnectInitialDelay)
	}
	if options.ReconnectMaxDelay != 0 {
		config.ReconnectMaxDelay = time.Duration(options.ReconnectMaxDelay)
	}
	if err := config.Validate(); err != nil {
		return ext.Config{}, err
	}
	return config, nil
}

func buildSessionConfig(options option.ExtrojanSessionOptions) (ext.Config, error) {
	return BuildSessionConfig(options)
}
