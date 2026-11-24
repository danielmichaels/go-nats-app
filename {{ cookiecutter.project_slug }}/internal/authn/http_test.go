package authn

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestRemote(t *testing.T) {
	h := &Handler{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	for _, tc := range []struct {
		peer, xff, want string
	}{
		{"203.0.113.9:1234", "198.51.100.1", "203.0.113.9"},
		{"10.0.0.2:1234", "", "10.0.0.2"},
		{"10.0.0.2:1234", "1.1.1.1, 198.51.100.1", "198.51.100.1"},
		{"10.0.0.2:1234", "198.51.100.1, 10.0.0.7", "198.51.100.1"},
		{"10.0.0.2:1234", "junk, 10.0.0.7", "10.0.0.7"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := h.Remote(r); got != tc.want {
			t.Errorf("peer %s, X-Forwarded-For %q: got %s, want %s", tc.peer, tc.xff, got, tc.want)
		}
	}
}
