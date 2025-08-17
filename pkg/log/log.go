package log

import (
	"net"
	"os"
	"strings"

	"github.com/bshuster-repo/logrus-logstash-hook"
	"github.com/sirupsen/logrus"
)

// Logger is the global logger instance.
var Logger = logrus.New()

func init() {
	// Default configuration
	Logger.SetOutput(os.Stdout)
	Logger.SetLevel(logrus.InfoLevel)
	Logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02 15:04:05.000",
	})

	// Integrate Logstash hook for ELK stack
	conn, err := net.Dial("tcp", "localhost:5044")
	if err != nil {
		Logger.Warnf("Failed to connect to Logstash: %v", err)
		return
	}
	hook := logrustash.New(conn, logrustash.DefaultFormatter(logrus.Fields{"type": "nova-proxy"}))
	Logger.AddHook(hook)
}

// SetLevel sets the global logger's level.
func SetLevel(level string) {
	lvl, err := logrus.ParseLevel(strings.ToLower(level))
	if err != nil {
		Logger.Warnf("Invalid log level '%s', using default 'info'", level)
		lvl = logrus.InfoLevel
	}
	Logger.SetLevel(lvl)
}
