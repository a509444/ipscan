package common

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/goflags"

	"ipscan/core/icmp"
	"ipscan/core/params"
	"ipscan/core/ping"
)

var (
	defaultEnd = []string{"1", "254", "2", "255"}
)

func Execute() {
	var opts params.Options
	var cidr goflags.StringSlice
	var end goflags.StringSlice
	var ports goflags.StringSlice

	var cmdIs bool
	var cmdIsa bool
	var cmdPs bool
	var cmdV bool

	flagSet := goflags.NewFlagSet()
	flagSet.CaseSensitive = true
	flagSet.SetDescription(GetBanner() + "powerful intranet segment spy tool")

	flagSet.CreateGroup("command", "Command Selector",
		flagSet.BoolVarP(&cmdIs, "is", "", false, "icmp segment discovery"),
		flagSet.BoolVarP(&cmdIsa, "isa", "", false, "icmp discover segments then scan all alive IPs"),
		flagSet.BoolVarP(&cmdPs, "ps", "", false, "ping segment discovery"),
		flagSet.BoolVarP(&cmdV, "v", "", false, "show version info"),
	)

	flagSet.CreateGroup("global", "Global Options",
		flagSet.StringSliceVarP(&cidr, "cidr", "c", nil, "specify spy cidr(e.g. 172.16.0.0/12)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&end, "end", "e", defaultEnd, "specify the ending digits of the ip", goflags.CommaSeparatedStringSliceOptions),
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

	flagSet.CreateGroup("icmp", "ICMP Options",
		flagSet.IntVarP(&opts.IcmpTimes, "times", "", 1, "number of icmp packets sent per ip"),
	)

	flagSet.CreateGroup("ping", "Ping Options",
		flagSet.IntVarP(&opts.PingTimes, "times", "", 1, "number of echo request messages be sent"),
	)

	_ = ports

	_ = flagSet.Parse()

	if hasHelpFlag(os.Args[1:]) {
		printUsage()
		printFlagSetUsage(flagSet)
		return
	}

	cmd := resolveFlagCommand(cmdIs, cmdIsa, cmdPs, cmdV)
	if cmd == "" {
		printUsage()
		return
	}

	if cmd == "version" {
		PrintVersion()
		return
	}

	opts.CIDR = append([]string(nil), cidr...)
	opts.End = append([]string(nil), end...)

	Init(&opts)

	switch cmd {
	case "icmpspy":
		icmp.Spy(&opts)
	case "icmpspyall":
		icmp.SpyAll(&opts)
	case "pingspy":
		ping.Spy(&opts)
	default:
		printUsage()
	}
}

func resolveFlagCommand(cmdIs, cmdIsa, cmdPs, cmdV bool) string {
	selected := []string{}
	if cmdIs {
		selected = append(selected, "icmpspy")
	}
	if cmdIsa {
		selected = append(selected, "icmpspyall")
	}
	if cmdPs {
		selected = append(selected, "pingspy")
	}
	if cmdV {
		selected = append(selected, "version")
	}

	if len(selected) == 0 {
		return ""
	}
	if len(selected) > 1 {
		fmt.Fprintln(os.Stderr, "please select only one command flag")
		return ""
	}
	return selected[0]
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

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "help" {
			return true
		}
	}
	return false
}

func printFlagSetUsage(flagSet *goflags.FlagSet) {
	if flagSet == nil {
		return
	}
	originalArgs := os.Args
	os.Args = []string{originalArgs[0], "-h"}
	flagSet.CommandLine.Usage()
	os.Args = originalArgs
}

func printUsage() {
	fmt.Printf("%s\n", GetBanner())
	fmt.Println("Usage:")
	fmt.Println("  ipscan -is|-isa|-ps|-v [flags]")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  ipscan -is -c 192.168.0.0/16")
	fmt.Println("  ipscan -isa -c 192.168.0.0/16")
}
