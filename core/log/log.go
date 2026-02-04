package log

import (
	"github.com/kataras/golog"
	"io"
	"os"
)

var Log = golog.New()

func InitLog(debug, silent bool) {
	if debug {
		Log.SetLevel("debug")
	}
	if silent {
		Log.SetLevel("error")
		Log.SetTimeFormat("")
	}
	logFile, err := os.OpenFile("ipscan.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	Log.SetOutput(io.MultiWriter(os.Stdout, logFile))
}
