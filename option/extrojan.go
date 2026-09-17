package option

import (
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

type ExtrojanSessionOptions struct {
	Connections           int                      `json:"connections,omitempty"`
	ResumeTimeout         badoption.Duration       `json:"resume_timeout,omitempty"`
	HeartbeatInterval     badoption.Duration       `json:"heartbeat_interval,omitempty"`
	LinkTimeout           badoption.Duration       `json:"link_timeout,omitempty"`
	RetransmitInterval    badoption.Duration       `json:"retransmit_interval,omitempty"`
	MaxUnackedBytes       *byteformats.MemoryBytes `json:"max_unacked_bytes,omitempty"`
	MaxReceiveBytes       *byteformats.MemoryBytes `json:"max_receive_bytes,omitempty"`
	MaxStreamSegments     int                      `json:"max_stream_segments,omitempty"`
	LaneQueueSize         int                      `json:"lane_queue_size,omitempty"`
	UDPQueueSize          int                      `json:"udp_queue_size,omitempty"`
	MaxUDPQueueBytes      *byteformats.MemoryBytes `json:"max_udp_queue_bytes,omitempty"`
	MaxUDPAssociations    int                      `json:"max_udp_associations,omitempty"`
	UDPIdleTimeout        badoption.Duration       `json:"udp_idle_timeout,omitempty"`
	LaneRotationInterval  badoption.Duration       `json:"lane_rotation_interval,omitempty"`
	MaxSessions           int                      `json:"max_sessions,omitempty"`
	MaxSessionsPerUser    int                      `json:"max_sessions_per_user,omitempty"`
	LegacyProbeTimeout    badoption.Duration       `json:"legacy_probe_timeout,omitempty"`
	ReconnectInitialDelay badoption.Duration       `json:"reconnect_initial_delay,omitempty"`
	ReconnectMaxDelay     badoption.Duration       `json:"reconnect_max_delay,omitempty"`
}

type ExtrojanInboundOptions struct {
	ListenOptions
	Users []TrojanUser `json:"users,omitempty"`
	InboundTLSOptionsContainer
	Fallback        *ServerOptions            `json:"fallback,omitempty"`
	FallbackForALPN map[string]*ServerOptions `json:"fallback_for_alpn,omitempty"`
	Multiplex       *InboundMultiplexOptions  `json:"multiplex,omitempty"`
	Transport       *V2RayTransportOptions    `json:"transport,omitempty"`
	Session         ExtrojanSessionOptions    `json:"session,omitempty"`
}

type ExtrojanOutboundOptions struct {
	DialerOptions
	ServerOptions
	Password string      `json:"password"`
	Network  NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Multiplex        *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport        *V2RayTransportOptions    `json:"transport,omitempty"`
	Session          ExtrojanSessionOptions    `json:"session,omitempty"`
	FallbackToTrojan *bool                     `json:"fallback_to_trojan,omitempty"`
}
