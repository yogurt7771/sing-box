package extrojan

type logicalAddr struct {
	network string
	address string
}

func (a logicalAddr) Network() string {
	return a.network
}

func (a logicalAddr) String() string {
	return a.address
}
