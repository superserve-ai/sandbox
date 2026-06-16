package secretsproxy

import (
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
)

func makeProxyAuthReq(headerValue string) *http.Request {
	r, _ := http.NewRequest(http.MethodConnect, "https://api.openai.com:443/", nil)
	if headerValue != "" {
		r.Header.Set("Proxy-Authorization", headerValue)
	}
	return r
}

func TestParseProxyAuthJWT(t *testing.T) {
	const jwtBody = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJzYi0xIn0.SIGNATURE"

	tests := []struct {
		name    string
		header  string
		wantErr error
		wantJWT string
	}{
		{
			name:    "missing header",
			header:  "",
			wantErr: ErrMissingProxyAuth,
		},
		{
			name:    "wrong scheme",
			header:  "Bearer abc",
			wantErr: ErrMalformedProxyAuth,
		},
		{
			name:    "empty credentials",
			header:  "Basic ",
			wantErr: ErrMalformedProxyAuth,
		},
		{
			name:    "not base64",
			header:  "Basic !!!notbase64!!!",
			wantErr: ErrMalformedProxyAuth,
		},
		{
			name:    "no colon",
			header:  "Basic " + base64.StdEncoding.EncodeToString([]byte("justjwt")),
			wantErr: ErrMalformedProxyAuth,
		},
		{
			name:    "trailing colon (empty JWT)",
			header:  "Basic " + base64.StdEncoding.EncodeToString([]byte("sb:")),
			wantErr: ErrMalformedProxyAuth,
		},
		{
			name:    "happy path (sb:jwt)",
			header:  "Basic " + base64.StdEncoding.EncodeToString([]byte("sb:"+jwtBody)),
			wantJWT: jwtBody,
		},
		{
			name:    "empty user portion accepted (':jwt')",
			header:  "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+jwtBody)),
			wantJWT: jwtBody,
		},
		{
			name:    "raw-std-encoding (no padding) accepted",
			header:  "Basic " + base64.RawStdEncoding.EncodeToString([]byte("u:"+jwtBody)),
			wantJWT: jwtBody,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotJWT, err := ParseProxyAuthJWT(makeProxyAuthReq(tc.header))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err: want %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotJWT != tc.wantJWT {
				t.Errorf("jwt: want %q, got %q", tc.wantJWT, gotJWT)
			}
		})
	}
}
