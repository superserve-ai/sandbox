// Verify the rendered Cloud Logging RE2 pattern against the API's ConsoleWriter.
package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/rs/zerolog"
)

func main() {
	pattern := regexp.MustCompile(os.Args[1])
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	for _, noColor := range []bool{false, true} {
		for _, level := range []zerolog.Level{zerolog.ErrorLevel, zerolog.WarnLevel, zerolog.InfoLevel} {
			var out bytes.Buffer
			logger := zerolog.New(zerolog.ConsoleWriter{Out: &out, TimeFormat: time.RFC3339, NoColor: noColor}).With().Timestamp().Caller().Logger()
			logger.WithLevel(level).Str("error", "ERR retry needed").Msg("usage entitlement requires operator recovery; inspect pending grants before collecting invoices")
			if got, want := pattern.Match(out.Bytes()), level == zerolog.ErrorLevel; got != want {
				panic(fmt.Sprintf("console severity mismatch: noColor=%t level=%s got=%t output=%q", noColor, level, got, out.String()))
			}
		}
	}
	fmt.Println("6 console severity fixtures passed")
}
