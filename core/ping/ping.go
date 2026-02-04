package ping

import (
	. "ipscan/core/log"
	"ipscan/core/misc"
	"ipscan/core/params"
	"ipscan/core/spy"
	"strconv"
)

var (
	times   string
	timeout string
)

func check(ip string) bool {
	if misc.IsPing(ip, times, timeout) {
		return true
	} else {
		return false
	}
}

func Spy(opts *params.Options) {
	Log.Info("use ping command to spy")
	times = strconv.Itoa(opts.PingTimes)
	timeout = strconv.Itoa(opts.Timeout)
	spy.Spy(opts, check)
}
