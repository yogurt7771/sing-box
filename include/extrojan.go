package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/extrojan"
)

func registerExtrojanInbound(registry *inbound.Registry) {
	extrojan.RegisterInbound(registry)
}

func registerExtrojanOutbound(registry *outbound.Registry) {
	extrojan.RegisterOutbound(registry)
}
