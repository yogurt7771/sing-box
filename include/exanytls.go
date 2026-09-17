package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/exanytls"
)

func registerExAnyTLSInbound(registry *inbound.Registry) {
	exanytls.RegisterInbound(registry)
}

func registerExAnyTLSOutbound(registry *outbound.Registry) {
	exanytls.RegisterOutbound(registry)
}
