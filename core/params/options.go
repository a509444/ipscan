package params

type Options struct {
	CIDR    []string
	End     []string
	Random  int
	Thread  int
	Timeout int
	Output  string
	Rapid   bool
	Special bool
	Force   bool
	Silent  bool
	Debug   bool

	IcmpTimes    int
	PingTimes    int
	ArpInterface string
	TcpPorts     []int
	UdpPorts     []int
}
