package main

import (
	"net"
	"strconv"

	"github.com/rs/zerolog"
)

// inheritedListeners picks the public and redirect listeners out of the
// sockets systemd passed, matched by port. Without a socket unit both are
// nil and the servers bind their addresses themselves.
func inheritedListeners(inherit func() ([]net.Listener, error), addr, redirectAddr string, log zerolog.Logger) (public, redirect net.Listener) {
	passed, err := inherit()
	if err != nil || len(passed) == 0 {
		return nil, nil
	}
	publicPort, redirectPort := listenPort(addr), listenPort(redirectAddr)
	for _, l := range passed {
		if l == nil {
			continue
		}
		ta, ok := l.Addr().(*net.TCPAddr)
		if !ok {
			_ = l.Close()
			continue
		}
		switch {
		case ta.Port == publicPort && public == nil:
			public = l
		case ta.Port == redirectPort && redirect == nil:
			redirect = l
		default:
			// A bare ListenStream can pass v4 and v6 fds; keep the first.
			log.Warn().Str("addr", ta.String()).Msg("inherited listener unused — closing")
			_ = l.Close()
		}
	}
	if public == nil {
		log.Fatal().Str("addr", addr).Msg("socket unit passed listeners but none matches PROXY_ADDR — check its ListenStream")
	}
	return public, redirect
}

func listenPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return -1
	}
	return n
}
