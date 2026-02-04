package arp

import (
	. "ipscan/core/log"
	"ipscan/core/params"
	"ipscan/core/spy"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/mdlayher/arp"
)

var (
	timeout time.Duration
	iface   string
)

var goos = runtime.GOOS

func checkOs() {
	if goos == "windows" {
		Log.Error("the arpspy module does not support windows system")
		os.Exit(1)
	}
}

func check(ip string) bool {
	// Ensure valid network interface
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		Log.Error(err)
		return false
	}
	// Set up ARP client with socket
	c, err := arp.Dial(ifi)
	if err != nil {
		Log.Error(err)
		return false
	}
	defer c.Close()

	// Set request deadline from flag
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		Log.Error(err)
		return false
	}

	// Request hardware address for IP address
	host := net.ParseIP(ip).To4()
	mac, err := c.Resolve(host)
	if err != nil {
		Log.Error(err)
		return false
	}
	Log.Debug("%s %s", ip, mac)
	return true
}

func Spy(opts *params.Options) {
	Log.Info("use arp protocol to spy")
	checkOs()
	iface = opts.ArpInterface
	timeout = time.Duration(opts.Timeout) * time.Millisecond
	spy.Spy(opts, check)
}
