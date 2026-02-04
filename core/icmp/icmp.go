package icmp

import (
	"github.com/go-ping/ping"
	. "ipscan/core/log"
	"ipscan/core/params"
	"ipscan/core/spy"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var (
	times   int
	timeout time.Duration
	goos    = runtime.GOOS
)

func checkPermission() {
	if goos == "linux" {
		cmd := exec.Command("cat", "/proc/sys/net/ipv4/ping_group_range")
		buf, _ := cmd.Output()
		str := string(buf)
		if !strings.Contains(str, "2147483647") {
			Log.Error("you must manually execute the command to grant the right to send icmp package\n",
				"sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"",
			)
			Log.Info("or you can try to use the pingspy module")
			os.Exit(1)
		}
	}
}

func check(ip string) bool {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		Log.Debug(err.Error())
		return false
	}
	if goos == "windows" {
		pinger.SetPrivileged(true)
	}
	pinger.Count = times
	pinger.Timeout = timeout
	err = pinger.Run()
	if err != nil {
		Log.Debug(err.Error())
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv > 0 {
		return true
	}
	return false
}

func Spy(opts *params.Options) {
	Log.Info("use icmp protocol to spy")
	checkPermission()
	times = opts.IcmpTimes
	timeout = time.Duration(opts.Timeout) * time.Millisecond
	spy.Spy(opts, check)
}

func SpyAll(opts *params.Options) {
	Log.Info("use icmp protocol to spy all alive hosts in reachable segments")
	checkPermission()
	times = opts.IcmpTimes
	timeout = time.Duration(opts.Timeout) * time.Millisecond
	spy.SpyAllAliveIPs(opts, check)
}
