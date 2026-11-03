package innerva

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Redwood-Labs-US/innerva-client-go/internal/wire"
)

func TestCreateAccessSignsFundingNeutralRequest(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thumbprint := testKeyID(t, key)
	fixedNow := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		verifyProof(t, request, body, &key.PublicKey, thumbprint, fixedNow)
		if strings.Contains(string(body), "purchase") || strings.Contains(string(body), "pool") || strings.Contains(string(body), "customer") {
			t.Errorf("request exposed fulfillment/source fields: %s", body)
		}
		var accessRequest wire.AccessRequest
		if err := json.Unmarshal(body, &accessRequest); err != nil {
			t.Error(err)
		}
		var responseBody bytes.Buffer
		_ = json.NewEncoder(&responseBody).Encode(map[string]any{
			"protocol_version": "0.1", "request_id": "ar_aaaaaaaaaaaaaaaaaaaaaaaaaa",
			"instance_id": "inst_bbbbbbbbbbbbbbbbbbbbbbbbbb", "expires_in": 900,
			"continue": map[string]any{"uri": "https://innerva.test/v1/access-requests/ar_aaaaaaaaaaaaaaaaaaaaaaaaaa/continue", "access_token": map[string]string{"value": "ict1_abcdefghijklmnopqrstuvwxyz1234567890ABCDE"}, "wait": 0},
			"interact": map[string]string{"redirect": "https://innerva.test/interact/ix_cccccccccccccccccccccccccc", "finish": "if1_abcdefghijklmnopqrstuvwxyz1234567890ABCDE"},
		})
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(&responseBody), Request: request,
		}, nil
	})}

	client, err := New(Config{
		BaseURL: "https://innerva.test", DisplayName: "Example", DisplayURI: "https://example.test",
		CallbackURI: "https://example.test/callback", HTTPClient: httpClient,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return fixedNow }
	pending, err := client.CreateAccess(context.Background(), RequestOptions{IdempotencyKey: "request-1"})
	if err != nil {
		t.Fatal(err)
	}
	if pending.RequestID == "" || pending.InteractionURI == "" {
		t.Fatalf("pending = %#v", pending)
	}
}

func TestCallbackBindingRejectsSubstitution(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, err := New(Config{
		BaseURL: "https://api.example", DisplayName: "Example", DisplayURI: "https://example.test",
		CallbackURI: "https://example.test/callback",
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	pending := PendingAccess{
		ClientFinish: "client", ServerFinish: "server", AccessEndpoint: "https://api.example/v1/access-requests",
	}
	hash := interactionHash("client", "server", "reference", pending.AccessEndpoint)
	if !client.ValidateCallback(pending, "reference", hash) {
		t.Fatal("valid callback rejected")
	}
	if client.ValidateCallback(pending, "substituted", hash) {
		t.Fatal("substituted interaction reference accepted")
	}
}

func TestContinueRejectsCrossOriginManagementURI(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thumbprint := testKeyID(t, key)
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var responseBody bytes.Buffer
		_ = json.NewEncoder(&responseBody).Encode(map[string]any{
			"access_token": map[string]any{
				"value": "iat1_abcdefghijklmnopqrstuvwxyz1234567890ABCDE",
				"access": []any{map[string]any{
					"type": "innerva_inference", "actions": []string{"responses.create"},
					"models": []string{"innerva:standard"}, "grant_id": "gr_aaaaaaaaaaaaaaaaaaaaaaaaaa",
					"credits": map[string]any{"grant_limit": 1000, "grant_remaining": 1000, "unit": "innerva_credit"},
				}},
				"expires_in": 900,
				"key":        map[string]string{"jkt": thumbprint},
				"manage": map[string]any{
					"uri":          "https://attacker.example/v1/capabilities/cap_bad",
					"access_token": map[string]string{"value": "imt1_abcdefghijklmnopqrstuvwxyz1234567890ABCDE"},
				},
			},
		})
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(&responseBody), Request: request,
		}, nil
	})}
	client, err := New(Config{
		BaseURL: "https://api.example", DisplayName: "Example", DisplayURI: "https://example.test",
		CallbackURI: "https://example.test/callback", HTTPClient: httpClient,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	pending := PendingAccess{
		ContinuationURI:   "https://api.example/v1/access-requests/ar_aaaaaaaaaaaaaaaaaaaaaaaaaa/continue",
		ContinuationToken: "ict1_abcdefghijklmnopqrstuvwxyz1234567890ABCDE",
		ClientFinish:      "client",
		ServerFinish:      "server",
		AccessEndpoint:    "https://api.example/v1/access-requests",
	}
	callbackHash := interactionHash("client", "server", "reference", pending.AccessEndpoint)
	if _, err := client.Continue(context.Background(), pending, "reference", callbackHash); err == nil || !strings.Contains(err.Error(), "management URI") {
		t.Fatalf("cross-origin management URI error = %v", err)
	}
}

func TestClientRequiresHTTPSOutsideLoopback(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	configuration := Config{
		BaseURL: "http://api.example", DisplayName: "Example", DisplayURI: "https://example.test",
		CallbackURI: "https://example.test/callback",
	}
	if _, err := New(configuration, key); err == nil {
		t.Fatal("accepted plaintext HTTP for a remote Innerva origin")
	}
	configuration.BaseURL = "http://localhost:8080"
	if _, err := New(configuration, key); err != nil {
		t.Fatalf("rejected loopback development origin: %v", err)
	}
}

func TestClientDoesNotFollowProtocolRedirects(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	calls := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{"http://api.example/credential-capture"}},
			Body:       io.NopCloser(strings.NewReader("redirected")),
			Request:    request,
		}, nil
	})}
	client, err := New(Config{
		BaseURL: "https://api.example", DisplayName: "Example", DisplayURI: "https://example.test",
		CallbackURI: "https://example.test/callback", HTTPClient: httpClient,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateAccess(context.Background(), RequestOptions{}); err == nil {
		t.Fatal("accepted a redirected protocol response")
	}
	if calls != 1 {
		t.Fatalf("protocol redirect made %d HTTP calls, want 1", calls)
	}
}

func TestControlRequestsRetainABoundedDefaultTimeout(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	client, err := New(Config{
		BaseURL: "https://api.example", DisplayName: "Example", DisplayURI: "https://example.test",
		CallbackURI: "https://example.test/callback", HTTPClient: httpClient,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	client.requestTimeout = 5 * time.Millisecond
	started := time.Now()
	if _, err := client.CreateAccess(context.Background(), RequestOptions{}); err == nil {
		t.Fatal("control request ignored its default timeout")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("control request timeout took %s", elapsed)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestNewNormalizesBaseURLAuthorityToTheCanonicalOrigin(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for base, want := range map[string]string{
		"https://Innerva.NET:443":  "innerva.net",
		"https://innerva.net/":     "innerva.net",
		"https://innerva.net:8443": "innerva.net:8443",
		"http://LOCALHOST:80":      "localhost",
		"http://[::1]:8080":        "[::1]:8080",
	} {
		client, err := New(Config{
			BaseURL: base, DisplayName: "Example", DisplayURI: "https://example.test",
			CallbackURI: "https://example.test/callback",
		}, key)
		if err != nil {
			t.Fatalf("New(%q): %v", base, err)
		}
		if client.baseURL.Host != want {
			t.Errorf("New(%q) authority = %q, want %q", base, client.baseURL.Host, want)
		}
		// The server advertises its canonical origin; it must match.
		if err := client.requireSameOrigin(client.baseURL.Scheme + "://" + want + "/v1/responses"); err != nil {
			t.Errorf("New(%q) rejects its own canonical origin: %v", base, err)
		}
	}
}
