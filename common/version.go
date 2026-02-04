package common

const VERSION = "v0.1.0"

func GetVersion() string {
	return "ipscan: " + VERSION
}

func PrintVersion() {
	print(GetVersion())
}
