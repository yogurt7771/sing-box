package extrojan

import (
	"fmt"
	"time"
)

const (
	ProtocolVersion      = 1
	StreamChunkSize      = 16 * 1024
	DefaultMaxFrameSize  = 128 * 1024
	DefaultMaxUDPPayload = 65535
)

type Config struct {
	Connections           int
	ResumeTimeout         time.Duration
	HeartbeatInterval     time.Duration
	LinkTimeout           time.Duration
	RetransmitInterval    time.Duration
	MaxUnackedBytes       int
	MaxReceiveBytes       int
	MaxStreamSegments     int
	LaneQueueSize         int
	UDPQueueSize          int
	MaxUDPQueueBytes      int
	MaxUDPAssociations    int
	UDPIdleTimeout        time.Duration
	LaneRotationInterval  time.Duration
	MaxSessions           int
	MaxSessionsPerUser    int
	LegacyProbeTimeout    time.Duration
	ReconnectInitialDelay time.Duration
	ReconnectMaxDelay     time.Duration
	MaxFrameSize          int
}

func DefaultConfig() Config {
	return Config{
		Connections:           4,
		ResumeTimeout:         60 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		LinkTimeout:           10 * time.Second,
		RetransmitInterval:    time.Second,
		MaxUnackedBytes:       8 * 1024 * 1024,
		MaxReceiveBytes:       8 * 1024 * 1024,
		MaxStreamSegments:     4096,
		LaneQueueSize:         256,
		UDPQueueSize:          256,
		MaxUDPQueueBytes:      8 * 1024 * 1024,
		MaxUDPAssociations:    1024,
		MaxSessions:           1024,
		MaxSessionsPerUser:    128,
		LegacyProbeTimeout:    3 * time.Second,
		ReconnectInitialDelay: 200 * time.Millisecond,
		ReconnectMaxDelay:     5 * time.Second,
		MaxFrameSize:          DefaultMaxFrameSize,
	}
}

// maxRecoveryBudget saturates RecoveryBudget instead of overflowing when a
// caller configures absurd durations.
const maxRecoveryBudget = time.Duration(1<<63 - 1)

// RecoveryBudget is the upper bound on how long a logical session can be
// unavailable while still being recoverable: detecting that every carrier is
// gone, the resume window itself, reconnect backoff and one retransmission
// interval, plus a small margin. Layers stacked on the reliable stream size
// their own failure timeouts against it so they do not give up on a session
// that is still inside a recoverable window.
func (c Config) RecoveryBudget() time.Duration {
	budget := time.Second
	for _, component := range []time.Duration{
		c.LinkTimeout,
		c.ResumeTimeout,
		c.ReconnectMaxDelay,
		c.ReconnectMaxDelay,
		c.RetransmitInterval,
	} {
		if component >= maxRecoveryBudget-budget {
			return maxRecoveryBudget
		}
		budget += component
	}
	return budget
}

func (c Config) Validate() error {
	if c.Connections < 1 || c.Connections > 16 {
		return fmt.Errorf("connections must be between 1 and 16")
	}
	if c.ResumeTimeout <= 0 {
		return fmt.Errorf("resume_timeout must be positive")
	}
	if c.HeartbeatInterval <= 0 {
		return fmt.Errorf("heartbeat_interval must be positive")
	}
	if c.LinkTimeout <= c.HeartbeatInterval {
		return fmt.Errorf("link_timeout must be greater than heartbeat_interval")
	}
	if c.RetransmitInterval <= 0 {
		return fmt.Errorf("retransmit_interval must be positive")
	}
	if c.MaxUnackedBytes < StreamChunkSize {
		return fmt.Errorf("max_unacked_bytes must be at least %d", StreamChunkSize)
	}
	if c.MaxReceiveBytes < StreamChunkSize {
		return fmt.Errorf("max_receive_bytes must be at least %d", StreamChunkSize)
	}
	if c.MaxStreamSegments < 16 || c.MaxStreamSegments > 8192 {
		return fmt.Errorf("max_stream_segments must be between 16 and 8192")
	}
	if c.LaneQueueSize < 1 {
		return fmt.Errorf("lane_queue_size must be positive")
	}
	if c.UDPQueueSize < 1 {
		return fmt.Errorf("udp_queue_size must be positive")
	}
	if c.MaxUDPQueueBytes < DefaultMaxUDPPayload {
		return fmt.Errorf("max_udp_queue_bytes must be at least %d", DefaultMaxUDPPayload)
	}
	if c.MaxUDPAssociations < 1 {
		return fmt.Errorf("max_udp_associations must be positive")
	}
	if c.UDPIdleTimeout < 0 {
		return fmt.Errorf("udp_idle_timeout must not be negative")
	}
	if c.LaneRotationInterval < 0 {
		return fmt.Errorf("lane_rotation_interval must not be negative")
	}
	if c.MaxSessions < 1 {
		return fmt.Errorf("max_sessions must be positive")
	}
	if c.MaxSessionsPerUser < 1 || c.MaxSessionsPerUser > c.MaxSessions {
		return fmt.Errorf("max_sessions_per_user must be between 1 and max_sessions")
	}
	if c.LegacyProbeTimeout <= 0 {
		return fmt.Errorf("legacy_probe_timeout must be positive")
	}
	if c.ReconnectInitialDelay <= 0 {
		return fmt.Errorf("reconnect_initial_delay must be positive")
	}
	if c.ReconnectMaxDelay < c.ReconnectInitialDelay {
		return fmt.Errorf("reconnect_max_delay must not be less than reconnect_initial_delay")
	}
	if c.MaxFrameSize < StreamChunkSize+9 || c.MaxFrameSize > 1024*1024 {
		return fmt.Errorf("max frame size is outside the supported range")
	}
	return nil
}
