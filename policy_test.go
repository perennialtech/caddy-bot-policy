package turnstile

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

var passThrough = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

func TestBlockIDFormat(t *testing.T) {
	id := newBlockID("ts-")
	suffix, ok := strings.CutPrefix(id, "ts-")
	if !ok || len(suffix) != 32 {
		t.Fatalf("invalid block ID: %q", id)
	}
	if _, err := hex.DecodeString(suffix); err != nil {
		t.Fatal(err)
	}
}
