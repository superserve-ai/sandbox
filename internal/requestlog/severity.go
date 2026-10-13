package requestlog

import "github.com/rs/zerolog"

// CloudSeverityHook retains zerolog's level while supplying the severity field
// recognized by Cloud Logging when JSON is collected from stdout.
type CloudSeverityHook struct{}

func (CloudSeverityHook) Run(e *zerolog.Event, level zerolog.Level, _ string) {
	severity := "DEFAULT"
	switch level {
	case zerolog.TraceLevel, zerolog.DebugLevel:
		severity = "DEBUG"
	case zerolog.InfoLevel:
		severity = "INFO"
	case zerolog.WarnLevel:
		severity = "WARNING"
	case zerolog.ErrorLevel:
		severity = "ERROR"
	case zerolog.FatalLevel:
		severity = "CRITICAL"
	case zerolog.PanicLevel:
		severity = "ALERT"
	}
	e.Str("severity", severity)
}
