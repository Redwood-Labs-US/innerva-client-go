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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInferSignsAndValidatesNormalizedStream(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thumbprint := testKeyID(t, key)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		verifyProof(t, request, body, &key.PublicKey, thumbprint, now)
		if request.Header.Get("Authorization") != "Innerva inference-token" || request.Header.Get("Idempotency-Key") != "inference-1" {
			t.Errorf("inference headers = %v", request.Header)
		}
		stream := strings.Join([]string{
			`event: response.created`,
			`data: {"type":"response.created","response":{"id":"res_aaaaaaaaaaaaaaaaaaaaaaaaaa","model":"innerva:standard","status":"in_progress"}}`,
			``,
			`event: response.output_text.delta`,
			`data: {"type":"response.output_text.delta","response_id":"res_aaaaaaaaaaaaaaaaaaaaaaaaaa","delta":"hello"}`,
			``,
			`event: response.completed`,
			`data: {"type":"response.completed","response":{"id":"res_aaaaaaaaaaaaaaaaaaaaaaaaaa","model":"innerva:standard","status":"completed","usage":{"input_units":2,"output_units":1},"credits":{"charged":3,"unit":"innerva_credit","capped":false}}}`,
			``,
		}, "\n")
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream; charset=utf-8"}},
			Body: io.NopCloser(strings.NewReader(stream)), Request: request,
		}, nil
	})}
	client, err := New(Config{
		BaseURL: "https://innerva.test", DisplayName: "Example", DisplayURI: "https://example.test",
		CallbackURI: "https://example.test/callback", HTTPClient: httpClient,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }

	capability := Capability{Value: "inference-token"}
	result, err := client.Infer(context.Background(), &capability, "hello", 10, "inference-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.OperationID != "res_aaaaaaaaaaaaaaaaaaaaaaaaaa" || result.Output != "hello" ||
		result.Status != "completed" || result.CreditsCharged != 3 {
		t.Fatalf("inference result = %#v", result)
	}
}

func TestInferenceStreamRejectsSubstitutionAndMissingTerminal(t *testing.T) {
	t.Parallel()
	for _, stream := range []string{
		"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"res_one\"}}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"response_id\":\"res_other\",\"delta\":\"x\"}\n\n",
		"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"res_one\"}}\n\n",
		"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"res_aaaaaaaaaaaaaaaaaaaaaaaaaa\",\"model\":\"innerva:standard\",\"status\":\"in_progress\"},\"unexpected\":true}\n\n",
	} {
		if _, err := decodeInferenceStream(strings.NewReader(stream)); err == nil {
			t.Fatalf("accepted invalid stream %q", stream)
		}
	}
}

func FuzzInferenceStreamNeverPanics(fuzzer *testing.F) {
	fuzzer.Add([]byte("event: response.created\ndata: {}\n\n"))
	fuzzer.Add([]byte("event: error\ndata: {\"type\":\"error\"}\n\n"))
	fuzzer.Add([]byte("not-sse"))
	fuzzer.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 2<<20 {
			t.Skip()
		}
		_, _ = decodeInferenceStream(bytes.NewReader(input))
	})
}

func TestInferenceRefreshesCapabilityOnceForConcurrentRequests(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thumbprint := testKeyID(t, key)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	managementURI := "https://innerva.test/v1/capabilities/cap_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	var rotations atomic.Int32
	var inferences atomic.Int32
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/rotate") {
			rotations.Add(1)
			time.Sleep(10 * time.Millisecond)
			var body bytes.Buffer
			_ = json.NewEncoder(&body).Encode(map[string]any{"access_token": map[string]any{
				"value": "fresh-inference-token", "expires_in": 900,
				"key": map[string]string{"jkt": thumbprint},
				"access": []any{map[string]any{
					"type": "innerva_inference", "actions": []string{"responses.create"},
					"models": []string{"innerva:standard"}, "grant_id": "gr_aaaaaaaaaaaaaaaaaaaaaaaaaa",
					"credits": map[string]any{"grant_limit": 100, "grant_remaining": 100, "unit": "innerva_credit"},
				}},
				"manage": map[string]any{"uri": managementURI, "access_token": map[string]string{"value": "management-token"}},
			}})
			return &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(&body), Request: request,
			}, nil
		}
		inferences.Add(1)
		return inferenceResponse(request, "fresh-inference-token"), nil
	})}
	client, err := New(Config{
		BaseURL: "https://innerva.test", DisplayName: "Example", DisplayURI: "https://example.test",
		CallbackURI: "https://example.test/callback", HTTPClient: httpClient,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	capability := Capability{
		Value: "expired-inference-token", ManagementToken: "management-token", ManagementURI: managementURI,
		ExpiresAt: now.Add(-time.Second),
	}

	const requests = 8
	errors := make(chan error, requests)
	var wait sync.WaitGroup
	wait.Add(requests)
	for range requests {
		go func() {
			defer wait.Done()
			_, err := client.Infer(context.Background(), &capability, "hello", 10, "concurrent-refresh")
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if rotations.Load() != 1 || inferences.Load() != requests || capability.Value != "fresh-inference-token" {
		t.Fatalf("concurrent refresh made %d rotations and %d inferences with capability %q", rotations.Load(), inferences.Load(), capability.Value)
	}
}

func TestInferenceUsesCallerDeadlineInsteadOfShortJSONRequestTimeout(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		select {
		case <-time.After(20 * time.Millisecond):
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
		return inferenceResponse(request, "inference-token"), nil
	})}
	client, err := New(Config{
		BaseURL: "https://innerva.test", DisplayName: "Example", DisplayURI: "https://example.test",
		CallbackURI: "https://example.test/callback", HTTPClient: httpClient,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	client.requestTimeout = time.Millisecond
	capability := Capability{Value: "inference-token"}
	if _, err := client.Infer(context.Background(), &capability, "hello", 10, "delayed-inference"); err != nil {
		t.Fatalf("delayed inference inherited JSON request timeout: %v", err)
	}
}

func TestInferenceRefreshesExpiringCapabilityBeforeStartingStream(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thumbprint := testKeyID(t, key)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	managementURI := "https://innerva.test/v1/capabilities/cap_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	calls := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			if request.URL.Path != "/v1/capabilities/cap_aaaaaaaaaaaaaaaaaaaaaaaaaa/rotate" ||
				request.Header.Get("Authorization") != "Innerva management-token" {
				t.Errorf("refresh request = %s with %q", request.URL.Path, request.Header.Get("Authorization"))
			}
			var body bytes.Buffer
			_ = json.NewEncoder(&body).Encode(map[string]any{"access_token": map[string]any{
				"value": "fresh-inference-token", "expires_in": 900,
				"key": map[string]string{"jkt": thumbprint},
				"access": []any{map[string]any{
					"type": "innerva_inference", "actions": []string{"responses.create"},
					"models": []string{"innerva:standard"}, "grant_id": "gr_aaaaaaaaaaaaaaaaaaaaaaaaaa",
					"credits": map[string]any{"grant_limit": 100, "grant_remaining": 100, "unit": "innerva_credit"},
				}},
				"manage": map[string]any{"uri": managementURI, "access_token": map[string]string{"value": "management-token"}},
			}})
			return &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(&body), Request: request,
			}, nil
		case 2:
			if request.URL.Path != "/v1/responses" || request.Header.Get("Authorization") != "Innerva fresh-inference-token" {
				t.Errorf("inference request = %s with %q", request.URL.Path, request.Header.Get("Authorization"))
			}
			return inferenceResponse(request, "fresh-inference-token"), nil
		default:
			t.Fatalf("unexpected SDK request %d: %s", calls, request.URL)
			return nil, nil
		}
	})}
	client, err := New(Config{
		BaseURL: "https://innerva.test", DisplayName: "Example", DisplayURI: "https://example.test",
		CallbackURI: "https://example.test/callback", HTTPClient: httpClient,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	capability := Capability{
		Value: "expired-inference-token", ManagementToken: "management-token", ManagementURI: managementURI,
		CapabilityID: "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa", GrantID: "gr_aaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpiresAt: now.Add(-time.Second),
	}
	if _, err := client.Infer(context.Background(), &capability, "hello", 10, "refresh-inference"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || capability.Value != "fresh-inference-token" || !capability.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("refreshed capability = %#v after %d calls", capability, calls)
	}
}

func inferenceResponse(request *http.Request, token string) *http.Response {
	stream := strings.Join([]string{
		`event: response.created`,
		`data: {"type":"response.created","response":{"id":"res_aaaaaaaaaaaaaaaaaaaaaaaaaa","model":"innerva:standard","status":"in_progress"}}`,
		``,
		`event: response.completed`,
		`data: {"type":"response.completed","response":{"id":"res_aaaaaaaaaaaaaaaaaaaaaaaaaa","model":"innerva:standard","status":"completed","usage":{"input_units":1,"output_units":1},"credits":{"charged":2,"unit":"innerva_credit","capped":false}}}`,
		``,
	}, "\n")
	if request.Header.Get("Authorization") != "Innerva "+token {
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("unauthorized")), Request: request}
	}
	return &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(stream)), Request: request,
	}
}
