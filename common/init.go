package common

import (
	"ipscan/core/log"
	"ipscan/core/misc"
	"ipscan/core/params"
)

func Init(opts *params.Options) {
	log.InitLog(opts.Debug, opts.Silent)
	misc.RecEnvInfo()
}
