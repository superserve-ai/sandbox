package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRetirementCheckFailsClosed(t *testing.T) {
	for _, body := range []string{`{"safe_to_power_off":false,"blockers":["paused ownership"]}`, `{}`, `invalid`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		c := client{base: server.URL, token: "operator"}
		if err := c.drainStatus("host-a", true); err == nil {
			t.Fatal("missing retirement proof accepted", body)
		}
		server.Close()
	}
}
