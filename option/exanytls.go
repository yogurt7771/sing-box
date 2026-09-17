package option

// ExAnyTLS preserves the complete AnyTLS configuration surface and replaces
// only each AnyTLS session's underlying connection with a resumable extrojan
// session.
type ExAnyTLSInboundOptions struct {
	AnyTLSInboundOptions
	Transport *V2RayTransportOptions `json:"transport,omitempty"`
	Session   ExtrojanSessionOptions `json:"session,omitempty"`
}

type ExAnyTLSOutboundOptions struct {
	AnyTLSOutboundOptions
	Transport        *V2RayTransportOptions `json:"transport,omitempty"`
	Session          ExtrojanSessionOptions `json:"session,omitempty"`
	FallbackToAnyTLS *bool                  `json:"fallback_to_anytls,omitempty"`
}
