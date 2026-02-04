package spy

import (
	"fmt"
	. "ipscan/core/log"
	"ipscan/core/misc"
	"ipscan/core/params"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	thread int
	path   string
	rapid  bool
	force  bool
)

type outputFormatter func(string) string

func goSpy(ips [][]string, check func(ip string) bool, formatter outputFormatter, writeOutput bool) []string {
	var online []string
	var wg sync.WaitGroup
	var ipc = make(chan []string, 10000)
	var onc = make(chan string, 1000)
	var count int32

	if ips == nil {
		return online
	}
	go func() {
		for _, ipg := range ips {
			ipc <- ipg
		}
		defer close(ipc)
	}()

	// scan workers
	for i := 0; i < thread; i++ {
		wg.Add(1)
		go func(ipc chan []string) {
			for ipg := range ipc {
				for _, ip := range ipg {
					if check(ip) {
						online = append(online, ip)
						Log.Debugf("%s alive", ip)
						out := formatter(ip)
						Log.Printf("%s", out)
						if writeOutput {
							s := fmt.Sprintf("%s\n", out)
							onc <- s
						}
						// if a host in this /24 is alive, skip remaining unless forced
						if !force {
							break
						}
					} else {
						Log.Debugf("%s dead", ip)
						continue
					}
				}
				atomic.AddInt32(&count, int32(len(ipg)))
			}
			defer wg.Done()
		}(ipc)
	}

	if writeOutput {
		// output writer
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			Log.Error(err.Error())
		}
		defer file.Close()

		go func(onc chan string) {
			for s := range onc {
				_, err := file.WriteString(s)
				if err != nil {
					Log.Error(err.Error())
				}
			}
		}(onc)
	}

	// stats goroutine
	num := len(ips[0])
	wg.Add(1)
	go func() {
		all := float64(len(ips) * num)
		i := 0
		for {
			time.Sleep(10 * time.Second)
			i += 1
			spied := float64(count)
			speed := float64(count) / (float64(i) * 10)
			remain := (all - spied) / speed
			Log.Infof("all: %.0f spied: %.0f ratio: %.2f speed: %.2f it/s remain: %.0fs",
				all, spied, spied/all, speed, remain)
			if all == spied {
				wg.Done()
				break
			}
		}
	}()

	wg.Wait()
	return online
}

func formatAliveCIDR(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Sprintf("%s/24", ip)
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return fmt.Sprintf("%s/24", ip)
	}
	ipv4[3] = 1
	return fmt.Sprintf("%s/24", ipv4.String())
}

func setThread(i int, isRapid bool) int {
	if isRapid {
		return runtime.NumCPU() * 40
	}
	if i == 0 {
		return runtime.NumCPU() * 20
	}
	return i
}

func genNetIP(start, end net.IP) []net.IP {
	var netip []net.IP
	// 10.0.0.0 - 10.0.0.255 or 10.0.0.0 - 10.0.10.255
	if start[0] == end[0] && start[1] == end[1] {
		for k := start[2]; k <= end[2]; k++ {
			ip := make(net.IP, len(start))
			copy(ip, start)
			ip[2] = k
			netip = append(netip, ip)
			if k == 255 {
				break
			}
		}
	}
	// 10.0.0.0 - 10.10.255.255
	if start[0] == end[0] && start[1] != end[1] {
		for j := start[1]; j <= end[1]; j++ {
			for k := start[2]; k <= end[2]; k++ {
				ip := make(net.IP, len(start))
				copy(ip, start)
				ip[1] = j
				ip[2] = k
				netip = append(netip, ip)
				if k == 255 {
					break
				}
			}
			if j == 255 {
				break
			}
		}
	}

	// 10.0.0.0 - 20.255.255.255
	if start[0] != end[0] {
		for i := start[0]; i <= end[0]; i++ {
			for j := start[1]; j <= end[1]; j++ {
				for k := start[2]; k <= end[2]; k++ {
					ip := make(net.IP, len(start))
					copy(ip, start)
					ip[0] = i
					ip[1] = j
					ip[2] = k
					netip = append(netip, ip)
					if k == 255 {
						break
					}
				}
				if j == 255 {
					break
				}
			}
			if i == 255 {
				break
			}
		}
	}
	return netip
}

func getNetIPS(cidrs []string) []net.IP {
	var netips []net.IP
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			Log.Fatal(err)
		}
		start := ipnet.IP
		end := misc.CalcBcstIP(ipnet)
		Log.Infof("%v is from %v to %v", cidr, start, end)
		netip := genNetIP(start, end)
		netips = append(netips, netip...)
	}
	return netips
}

func genAllCIDR() []string {
	var all []string
	c := [9]int{1, 32, 64, 96, 128, 160, 192, 224, 255}
	for i := 1; i <= 255; i++ {
		for j := 1; j <= 255; j++ {
			for _, k := range c {
				cidr := fmt.Sprintf("%v.%v.%v.0/24", i, j, k)
				all = append(all, cidr)
			}
		}
	}
	return all
}

func mergeCIDR(cidrs []string, special bool) []string {
	var all []string
	for _, cidr := range cidrs {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			Log.Error(err)
			continue
		}
		all = append(all, cidr)
	}
	if all != nil {
		return all
	}
	if all == nil {
		c := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}
		all = append(all, c...)
	}
	if special {
		if misc.IsPureIntranet() {
			Log.Debug("the current network environment is pure intranet")
			all = genAllCIDR()
		} else {
			c := []string{"100.64.0.0/10", "59.192.0.0/10", "3.1.0.0/10"}
			all = append(all, c...)
		}
	}
	return all
}

func setEndNum(nums []string, isRapid bool) []int {
	var tail []int
	if isRapid {
		tail = append(tail, 1)
		return tail
	}
	for _, s := range nums {
		i, err := strconv.Atoi(s)
		if err != nil {
			Log.Error(err)
			continue
		}
		if i >= 0 && i <= 255 {
			tail = append(tail, i)
		}
	}
	return tail
}

func setRandomNum(i int, isRapid bool) int {
	if isRapid {
		return 0
	}
	if i >= 0 && i <= 255 {
		return i
	}
	return 1
}

func Spy(opts *params.Options, check func(ip string) bool) {
	rapid = opts.Rapid
	thread = setThread(opts.Thread, opts.Rapid)
	Log.Debugf("%v threads", thread)
	path = opts.Output
	Log.Debugf("save path: %v", path)
	force = opts.Force
	number := setEndNum(opts.End, opts.Rapid)
	special := opts.Special
	cidrs := opts.CIDR
	allcidr := mergeCIDR(cidrs, special)
	Log.Debugf("all cidr %v", allcidr)
	netips := getNetIPS(allcidr)
	count := setRandomNum(opts.Random, opts.Rapid)
	ips := GenIPS(netips, number, count)
	goSpy(ips, check, formatAliveCIDR, true)
}

func SpyAllAliveIPs(opts *params.Options, check func(ip string) bool) {
	rapid = opts.Rapid
	thread = setThread(opts.Thread, opts.Rapid)
	Log.Debugf("%v threads", thread)
	originalPath := path
	phaseOnePath := "alive.txt"
	phaseTwoPath := "ip.txt"
	path = phaseOnePath
	Log.Debugf("save path: %v", path)

	number := setEndNum(opts.End, opts.Rapid)
	special := opts.Special
	cidrs := opts.CIDR
	allcidr := mergeCIDR(cidrs, special)
	Log.Debugf("all cidr %v", allcidr)
	netips := getNetIPS(allcidr)
	count := setRandomNum(opts.Random, opts.Rapid)
	ips := GenIPS(netips, number, count)

	online := goSpy(ips, check, formatAliveCIDR, true)
	aliveCIDRs := uniqueCIDRs(online)
	if len(aliveCIDRs) == 0 {
		path = originalPath
		return
	}

	fullNetIPs := getNetIPS(aliveCIDRs)
	fullEndNums := fullHostRange()
	fullIPS := GenIPS(fullNetIPs, fullEndNums, 0)

	previousForce := force
	force = true
	path = phaseTwoPath
	Log.Debugf("save path: %v", path)
	goSpy(fullIPS, check, formatAliveIP, true)
	force = previousForce
	path = originalPath
}

func formatAliveIP(ip string) string {
	return ip
}

func fullHostRange() []int {
	hosts := make([]int, 0, 254)
	for i := 1; i <= 254; i++ {
		hosts = append(hosts, i)
	}
	return hosts
}

func uniqueCIDRs(online []string) []string {
	seen := make(map[string]struct{})
	var cidrs []string
	for _, ip := range online {
		cidr := formatAliveCIDR(ip)
		if _, ok := seen[cidr]; ok {
			continue
		}
		seen[cidr] = struct{}{}
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}
