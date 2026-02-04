package core

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/goflags"

	"ipscan/core/arp"
	"ipscan/core/icmp"
	"ipscan/core/params"
	"ipscan/core/ping"
	"ipscan/core/tcp"
	"ipscan/core/udp"
)

var (
	defaultEnd = []string{"1", "254", "2", "255"}

	defaultTCPPorts = []string{"21", "22", "23", "80", "135", "139", "443", "445", "3389", "8080"}
	defaultUDPPorts = []string{"53", "123", "137", "161", "520", "523", "1645", "1701", "1900", "5353"}
)

func Execute() {
	cmd, globalArgs, cmdArgs := splitArgs(os.Args[1:])
	if cmd == "" {
		if hasHelpFlag(os.Args[1:]) {
			printUsage()
			var tmpCIDR goflags.StringSlice
			var tmpEnd goflags.StringSlice
			printFlagSetUsage(buildGlobalFlags(&params.Options{}, &tmpCIDR, &tmpEnd), nil)
			return
		}
		printUsage()
		return
	}

	var opts params.Options
	var cidr goflags.StringSlice
	var end goflags.StringSlice

	globalFlags := buildGlobalFlags(&opts, &cidr, &end)

	cmdFlags := buildCommandFlags(cmd, &opts)
	globalArgs, cmdArgs = repartitionArgs(globalFlags, cmdFlags, globalArgs, cmdArgs)

	if hasHelpFlag(cmdArgs) || hasHelpFlag(globalArgs) {
		printUsage()
		printFlagSetUsage(globalFlags, nil)
		printCommandUsage(cmd, cmdFlags)
		return
	}

	parseWithArgs(globalFlags, globalArgs)
	opts.CIDR = append([]string(nil), cidr...)
	opts.End = append([]string(nil), end...)

	Init(&opts)

	switch cmd {
	case "icmpspy":
		parseWithArgs(cmdFlags, cmdArgs)
		icmp.Spy(&opts)
	case "icmpspyall":
		parseWithArgs(cmdFlags, cmdArgs)
		icmp.SpyAll(&opts)
	case "pingspy":
		parseWithArgs(cmdFlags, cmdArgs)
		ping.Spy(&opts)
	case "arpspy":
		parseWithArgs(cmdFlags, cmdArgs)
		if strings.TrimSpace(opts.ArpInterface) == "" {
			fmt.Fprintln(os.Stderr, "interface is required for arpspy")
			return
		}
		arp.Spy(&opts)
	case "tcpspy":
		var ports goflags.StringSlice
		cmdFlags = buildTCPFlags(&opts, &ports)
		parseWithArgs(cmdFlags, cmdArgs)
		parsedPorts, err := parseIntSlice([]string(ports))
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}
		opts.TcpPorts = parsedPorts
		tcp.Spy(&opts)
	case "udpspy":
		var ports goflags.StringSlice
		cmdFlags = buildUDPFlags(&opts, &ports)
		parseWithArgs(cmdFlags, cmdArgs)
		parsedPorts, err := parseIntSlice([]string(ports))
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}
		opts.UdpPorts = parsedPorts
		udp.Spy(&opts)
	case "version":
		PrintVersion()
	default:
		printUsage()
	}
}

func parseWithArgs(flagSet *goflags.FlagSet, args []string) {
	originalArgs := os.Args
	os.Args = append([]string{originalArgs[0]}, args...)
	_ = flagSet.Parse()
	os.Args = originalArgs
}

func splitArgs(args []string) (cmd string, globalArgs []string, cmdArgs []string) {
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if resolved, ok := resolveCommand(arg); ok {
			return resolved, args[:i], args[i+1:]
		}
	}
	return "", args, nil
}

func resolveCommand(arg string) (string, bool) {
	switch arg {
	case "icmpspy", "is":
		return "icmpspy", true
	case "icmpspyall", "isa":
		return "icmpspyall", true
	case "pingspy", "ps":
		return "pingspy", true
	case "arpspy", "as":
		return "arpspy", true
	case "tcpspy", "ts":
		return "tcpspy", true
	case "udpspy", "us":
		return "udpspy", true
	case "version", "v":
		return "version", true
	default:
		return "", false
	}
}

func buildGlobalFlags(opts *params.Options, cidr *goflags.StringSlice, end *goflags.StringSlice) *goflags.FlagSet {
	flagSet := goflags.NewFlagSet()
	flagSet.CaseSensitive = true
	flagSet.SetDescription(GetBanner() + "powerful intranet segment spy tool")
	flagSet.CreateGroup("global", "Global Options",
		flagSet.StringSliceVarP(cidr, "cidr", "c", nil, "specify spy cidr(e.g. 172.16.0.0/12)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(end, "end", "e", defaultEnd, "specify the ending digits of the ip", goflags.CommaSeparatedStringSliceOptions),
		flagSet.IntVarP(&opts.Random, "random", "r", 1, "the number of random ending digits in ip"),
		flagSet.IntVarP(&opts.Thread, "thread", "t", 0, "number of concurrency"),
		flagSet.IntVarP(&opts.Timeout, "timeout", "m", 500, "packet sending timeout millisecond"),
		flagSet.StringVarP(&opts.Output, "output", "o", "alive.txt", "output alive result to file in text format"),
		flagSet.BoolVarP(&opts.Rapid, "rapid", "x", false, "rapid spy mode"),
		flagSet.BoolVarP(&opts.Special, "special", "i", false, "spy special intranet"),
		flagSet.BoolVarP(&opts.Force, "force", "f", false, "force spy all generated ip"),
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "show only alive cidr in output"),
		flagSet.BoolVarP(&opts.Debug, "debug", "d", false, "show debug information"),
	)
	return flagSet
}

func buildCommandFlags(cmd string, opts *params.Options) *goflags.FlagSet {
	switch cmd {
	case "icmpspy":
		flagSet := goflags.NewFlagSet()
		flagSet.CaseSensitive = true
		flagSet.SetDescription("icmpspy options")
		flagSet.CreateGroup("icmp", "ICMP Options",
			flagSet.IntVarP(&opts.IcmpTimes, "times", "t", 1, "number of icmp packets sent per ip"),
		)
		return flagSet
	case "icmpspyall":
		flagSet := goflags.NewFlagSet()
		flagSet.CaseSensitive = true
		flagSet.SetDescription("icmpspyall options")
		flagSet.CreateGroup("icmp", "ICMP Options",
			flagSet.IntVarP(&opts.IcmpTimes, "times", "t", 1, "number of icmp packets sent per ip"),
		)
		return flagSet
	case "pingspy":
		flagSet := goflags.NewFlagSet()
		flagSet.CaseSensitive = true
		flagSet.SetDescription("pingspy options")
		flagSet.CreateGroup("ping", "Ping Options",
			flagSet.IntVarP(&opts.PingTimes, "times", "t", 1, "number of echo request messages be sent"),
		)
		return flagSet
	case "arpspy":
		flagSet := goflags.NewFlagSet()
		flagSet.CaseSensitive = true
		flagSet.SetDescription("arpspy options")
		flagSet.CreateGroup("arp", "ARP Options",
			flagSet.StringVarP(&opts.ArpInterface, "interface", "i", "", "network interface to use for ARP request"),
		)
		return flagSet
	case "tcpspy":
		return buildTCPFlags(opts, nil)
	case "udpspy":
		return buildUDPFlags(opts, nil)
	default:
		return goflags.NewFlagSet()
	}
}

func buildTCPFlags(opts *params.Options, ports *goflags.StringSlice) *goflags.FlagSet {
	flagSet := goflags.NewFlagSet()
	flagSet.CaseSensitive = true
	flagSet.SetDescription("tcpspy options")
	if ports == nil {
		var tmp goflags.StringSlice
		ports = &tmp
	}
	flagSet.CreateGroup("tcp", "TCP Options",
		flagSet.StringSliceVarP(ports, "port", "p", defaultTCPPorts, "specify tcp port to spy", goflags.CommaSeparatedStringSliceOptions),
	)
	return flagSet
}

func buildUDPFlags(opts *params.Options, ports *goflags.StringSlice) *goflags.FlagSet {
	flagSet := goflags.NewFlagSet()
	flagSet.CaseSensitive = true
	flagSet.SetDescription("udpspy options")
	if ports == nil {
		var tmp goflags.StringSlice
		ports = &tmp
	}
	flagSet.CreateGroup("udp", "UDP Options",
		flagSet.StringSliceVarP(ports, "port", "p", defaultUDPPorts, "specify udp port to spy", goflags.CommaSeparatedStringSliceOptions),
	)
	return flagSet
}

func repartitionArgs(globalFlags, cmdFlags *goflags.FlagSet, globalArgs, cmdArgs []string) ([]string, []string) {
	allGlobal := append([]string{}, globalArgs...)
	allCmd := append([]string{}, cmdArgs...)

	if cmdFlags == nil || len(cmdArgs) == 0 {
		return allGlobal, allCmd
	}

	cmdFlagIndex := flagIndex(cmdFlags)
	globalFlagIndex := flagIndex(globalFlags)

	var newGlobal []string
	var newCmd []string
	i := 0
	for i < len(allCmd) {
		arg := allCmd[i]
		if !strings.HasPrefix(arg, "-") {
			newCmd = append(newCmd, arg)
			i++
			continue
		}

		name, valueProvided := splitFlag(arg)
		if name == "" {
			newCmd = append(newCmd, arg)
			i++
			continue
		}

		if cmdFlagIndex[name] {
			newCmd, i = consumeFlag(allCmd, i, arg, name, valueProvided, cmdFlags, newCmd)
			continue
		}

		if globalFlagIndex[name] {
			newGlobal, i = consumeFlag(allCmd, i, arg, name, valueProvided, globalFlags, newGlobal)
			continue
		}

		newCmd = append(newCmd, arg)
		i++
	}

	allGlobal = append(allGlobal, newGlobal...)
	allCmd = newCmd
	return allGlobal, allCmd
}

func flagIndex(flagSet *goflags.FlagSet) map[string]bool {
	flags := make(map[string]bool)
	if flagSet == nil || flagSet.CommandLine == nil {
		return flags
	}
	flagSet.CommandLine.VisitAll(func(fl *flag.Flag) {
		flags[fl.Name] = true
	})
	return flags
}

func consumeFlag(args []string, index int, raw, name string, valueProvided bool, flagSet *goflags.FlagSet, out []string) ([]string, int) {
	out = append(out, raw)
	if valueProvided {
		return out, index + 1
	}
	if flagExpectsValue(flagSet, name) && index+1 < len(args) {
		out = append(out, args[index+1])
		return out, index + 2
	}
	return out, index + 1
}

func flagExpectsValue(flagSet *goflags.FlagSet, name string) bool {
	if flagSet == nil || flagSet.CommandLine == nil {
		return false
	}
	fl := flagSet.CommandLine.Lookup(name)
	if fl == nil {
		return false
	}
	if boolFlag, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok {
		return !boolFlag.IsBoolFlag()
	}
	return true
}

func splitFlag(arg string) (name string, valueProvided bool) {
	trimmed := strings.TrimLeft(arg, "-")
	if trimmed == "" {
		return "", false
	}
	if strings.Contains(trimmed, "=") {
		parts := strings.SplitN(trimmed, "=", 2)
		return parts[0], true
	}
	return trimmed, false
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "help" {
			return true
		}
	}
	return false
}

func printFlagSetUsage(flagSet *goflags.FlagSet, extraArgs []string) {
	if flagSet == nil {
		return
	}
	originalArgs := os.Args
	args := []string{originalArgs[0], "-h"}
	if len(extraArgs) > 0 {
		args = append(args, extraArgs...)
	}
	os.Args = args
	flagSet.CommandLine.Usage()
	os.Args = originalArgs
}

func printCommandUsage(cmd string, cmdFlags *goflags.FlagSet) {
	if cmdFlags == nil {
		return
	}
	fmt.Printf("\n%s options:\n", cmd)
	printFlagSetUsage(cmdFlags, nil)
}

func parseIntSlice(values []string) ([]int, error) {
	parsed := make([]int, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		v, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("invalid integer value: %s", value)
		}
		parsed = append(parsed, v)
	}
	return parsed, nil
}

func printUsage() {
	fmt.Printf("%s\n", GetBanner())
	fmt.Println("Usage:")
	fmt.Println("  ipscan [global flags] <command> [command flags]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  icmpspy (is)   specify icmp protocol to spy")
	fmt.Println("  icmpspyall (isa)   discover reachable segments, then scan all alive IPs")
	fmt.Println("  pingspy (ps)   specify ping command to spy")
	fmt.Println("  arpspy (as)    specify arp protocol to spy")
	fmt.Println("  tcpspy (ts)    specify tcp protocol to spy")
	fmt.Println("  udpspy (us)    specify udp protocol to spy")
	fmt.Println("  version (v)    show version info")
	fmt.Println()
	fmt.Println("Example:")
	fmt.Println("  ipscan -c 192.168.0.0/16 is -t 2")
}
