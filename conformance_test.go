package innerva

// Shared conformance vectors: signing, hashing, and stream outcomes. The
// vectors are generated from the Innerva server's reference implementation and
// every client SDK (Go, Python, TypeScript, Swift) must pass them, which pins
// this module's standard-library signing code byte for byte to the verifier a
// deployed Innerva runs.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// vectorsDirectory finds the vectors at conformance/vectors in a mirror or
// downloaded tarball root, or at sdk/conformance/vectors in the source monorepo.
func vectorsDirectory(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{
		filepath.Join("conformance", "vectors"),
		filepath.Join("..", "conformance", "vectors"),
	} {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	t.Fatal("conformance vectors directory not found")
	return ""
}

func loadVectors(t *testing.T, name string, destination any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDirectory(t), name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, destination); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

type vectorJWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

func (jwk vectorJWK) public() publicJWK {
	return publicJWK{KTY: jwk.KTY, CRV: jwk.CRV, X: jwk.X, Y: jwk.Y}
}

type signingVectors struct {
	Algorithm      string `json:"algorithm"`
	SignatureLabel string `json:"signature_label"`
	Key            struct {
		JWK        vectorJWK `json:"jwk"`
		Thumbprint string    `json:"thumbprint"`
	} `json:"key"`
	Cases []struct {
		Name    string `json:"name"`
		Request struct {
			Method         string `json:"method"`
			TargetURI      string `json:"target_uri"`
			ContentType    string `json:"content_type"`
			Body           string `json:"body"`
			Authorization  string `json:"authorization"`
			IdempotencyKey string `json:"idempotency_key"`
		} `json:"request"`
		Nonce    string `json:"nonce"`
		Created  int64  `json:"created"`
		Expires  int64  `json:"expires"`
		Expected struct {
			ContentDigest  string `json:"content_digest"`
			SignatureInput string `json:"signature_input"`
			SignatureBase  string `json:"signature_base"`
			Signature      string `json:"signature"`
		} `json:"expected"`
	} `json:"cases"`
}

func vectorPrivateKey(t *testing.T, jwk vectorJWK) *ecdsa.PrivateKey {
	t.Helper()
	decode := func(value string) *big.Int {
		raw, err := rawURL.DecodeString(value)
		if err != nil || len(raw) != 32 {
			t.Fatalf("vector key coordinate %q is invalid", value)
		}
		return new(big.Int).SetBytes(raw)
	}
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: decode(jwk.X), Y: decode(jwk.Y)},
		D:         decode(jwk.D),
	}
	derived, err := jwkFromPublicKey(&key.PublicKey)
	if err != nil || derived != jwk.public() {
		t.Fatalf("vector public key does not round-trip: %v", err)
	}
	return key
}

// TestSigningVectors signs every vector request through the same code path the
// client uses and requires the exact Content-Digest, Signature-Input, and
// signature base, plus signatures that verify over the vector base.
func TestSigningVectors(t *testing.T) {
	var vectors signingVectors
	loadVectors(t, "signing.json", &vectors)
	if vectors.Algorithm != signatureAlgorithm || vectors.SignatureLabel != signatureLabel {
		t.Fatalf("vector profile %q/%q does not match the SDK", vectors.Algorithm, vectors.SignatureLabel)
	}
	key := vectorPrivateKey(t, vectors.Key.JWK)
	thumbprint, err := jwkThumbprint(vectors.Key.JWK.public())
	if err != nil || thumbprint != vectors.Key.Thumbprint {
		t.Fatalf("thumbprint %q want %q (%v)", thumbprint, vectors.Key.Thumbprint, err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no signing cases")
	}
	for _, signingCase := range vectors.Cases {
		t.Run(signingCase.Name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(
				context.Background(), signingCase.Request.Method, signingCase.Request.TargetURI,
				strings.NewReader(signingCase.Request.Body),
			)
			if err != nil {
				t.Fatal(err)
			}
			if signingCase.Request.ContentType != "" {
				digest := contentDigest([]byte(signingCase.Request.Body))
				if digest != signingCase.Expected.ContentDigest {
					t.Fatalf("content digest %q want %q", digest, signingCase.Expected.ContentDigest)
				}
				request.Header.Set("Content-Type", signingCase.Request.ContentType)
				request.Header.Set("Content-Digest", digest)
			}
			if signingCase.Request.Authorization != "" {
				request.Header.Set("Authorization", signingCase.Request.Authorization)
			}
			if signingCase.Request.IdempotencyKey != "" {
				request.Header.Set("Idempotency-Key", signingCase.Request.IdempotencyKey)
			}
			if err := signRequestWithNonce(
				request, key, thumbprint, time.Unix(signingCase.Created, 0), signingCase.Nonce,
			); err != nil {
				t.Fatal(err)
			}
			if got := request.Header.Get("Signature-Input"); got != signingCase.Expected.SignatureInput {
				t.Fatalf("signature input mismatch:\n%s\nwant:\n%s", got, signingCase.Expected.SignatureInput)
			}
			if !strings.Contains(signingCase.Expected.SignatureInput, ";expires="+
				strconv.FormatInt(signingCase.Expires, 10)+";") {
				t.Fatalf("vector expires %d is not in the signature input", signingCase.Expires)
			}
			components := coveredComponents(request.Header)
			base, err := signatureBase(request, components, strings.TrimPrefix(
				request.Header.Get("Signature-Input"), signatureLabel+"="))
			if err != nil {
				t.Fatal(err)
			}
			if base != signingCase.Expected.SignatureBase {
				t.Fatalf("signature base mismatch:\n%s\nwant:\n%s", base, signingCase.Expected.SignatureBase)
			}
			if !verifyES256(&key.PublicKey, signingCase.Expected.SignatureBase, signingCase.Expected.Signature) {
				t.Fatal("recorded vector signature does not verify over the vector base")
			}
			produced := strings.TrimSuffix(strings.TrimPrefix(request.Header.Get("Signature"), "sig1=:"), ":")
			if !verifyES256(&key.PublicKey, signingCase.Expected.SignatureBase, produced) {
				t.Fatal("SDK signature does not verify over the vector base")
			}
		})
	}
}

// TestHashingVectors covers JWK thumbprints, Content-Digest, and callback hashes.
func TestHashingVectors(t *testing.T) {
	var vectors struct {
		ThumbprintCases []struct {
			Name       string    `json:"name"`
			JWK        publicJWK `json:"jwk"`
			Thumbprint string    `json:"thumbprint"`
		} `json:"thumbprint_cases"`
		ContentDigestCases []struct {
			Name          string `json:"name"`
			BodyBase64    string `json:"body_base64"`
			ContentDigest string `json:"content_digest"`
		} `json:"content_digest_cases"`
		CallbackHashCases []struct {
			Name           string `json:"name"`
			ClientFinish   string `json:"client_finish"`
			ServerFinish   string `json:"server_finish"`
			InteractRef    string `json:"interact_ref"`
			AccessEndpoint string `json:"access_endpoint"`
			Hash           string `json:"hash"`
		} `json:"callback_hash_cases"`
	}
	loadVectors(t, "hashing.json", &vectors)
	if len(vectors.ThumbprintCases) == 0 || len(vectors.ContentDigestCases) == 0 || len(vectors.CallbackHashCases) == 0 {
		t.Fatal("hashing vectors are incomplete")
	}
	for _, thumbprintCase := range vectors.ThumbprintCases {
		thumbprint, err := jwkThumbprint(thumbprintCase.JWK)
		if err != nil || thumbprint != thumbprintCase.Thumbprint {
			t.Errorf("%s: thumbprint %q want %q (%v)", thumbprintCase.Name, thumbprint, thumbprintCase.Thumbprint, err)
		}
	}
	for _, digestCase := range vectors.ContentDigestCases {
		body, err := base64.StdEncoding.DecodeString(digestCase.BodyBase64)
		if err != nil {
			t.Fatalf("%s: %v", digestCase.Name, err)
		}
		if digest := contentDigest(body); digest != digestCase.ContentDigest {
			t.Errorf("%s: digest %q want %q", digestCase.Name, digest, digestCase.ContentDigest)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{
		BaseURL: "https://api.innerva.example", DisplayName: "Conformance",
		DisplayURI: "https://client.example", CallbackURI: "https://client.example/callback",
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, callbackCase := range vectors.CallbackHashCases {
		hash := interactionHash(callbackCase.ClientFinish, callbackCase.ServerFinish,
			callbackCase.InteractRef, callbackCase.AccessEndpoint)
		if hash != callbackCase.Hash {
			t.Errorf("%s: hash %q want %q", callbackCase.Name, hash, callbackCase.Hash)
		}
		pending := PendingAccess{
			ClientFinish: callbackCase.ClientFinish, ServerFinish: callbackCase.ServerFinish,
			AccessEndpoint: callbackCase.AccessEndpoint,
		}
		if !client.ValidateCallback(pending, callbackCase.InteractRef, callbackCase.Hash) {
			t.Errorf("%s: ValidateCallback rejected the vector hash", callbackCase.Name)
		}
	}
}

// TestStreamVectors drives every stream transcript through Infer and requires
// the outcome the vectors demand of every client.
func TestStreamVectors(t *testing.T) {
	var vectors struct {
		Cases []struct {
			Name   string `json:"name"`
			SSE    string `json:"sse"`
			Expect struct {
				Kind           string `json:"kind"`
				OperationID    string `json:"operation_id"`
				Output         string `json:"output"`
				InputUnits     int64  `json:"input_units"`
				OutputUnits    int64  `json:"output_units"`
				CreditsCharged int64  `json:"credits_charged"`
				CreditsCapped  bool   `json:"credits_capped"`
				ErrorCode      string `json:"error_code"`
			} `json:"expect"`
		} `json:"cases"`
	}
	loadVectors(t, "stream.json", &vectors)
	if len(vectors.Cases) == 0 {
		t.Fatal("no stream cases")
	}
	for _, streamCase := range vectors.Cases {
		t.Run(streamCase.Name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "text/event-stream")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte(streamCase.SSE))
			}))
			defer server.Close()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			client, err := New(Config{
				BaseURL: server.URL, DisplayName: "Conformance",
				DisplayURI: "https://client.example", CallbackURI: "https://client.example/callback",
			}, key)
			if err != nil {
				t.Fatal(err)
			}
			capability := &Capability{Value: "it1_conformance_inference_token_value"}
			result, err := client.Infer(context.Background(), capability, "conformance", 64, "op_conformance")
			expect := streamCase.Expect
			switch expect.Kind {
			case "completed", "incomplete":
				if err != nil {
					t.Fatalf("expected %s result, got error: %v", expect.Kind, err)
				}
				if result.OperationID != expect.OperationID || result.Output != expect.Output ||
					result.Status != expect.Kind || result.InputUnits != expect.InputUnits ||
					result.OutputUnits != expect.OutputUnits || result.CreditsCharged != expect.CreditsCharged ||
					result.CreditsCapped != expect.CreditsCapped {
					t.Fatalf("result %+v does not match vector %+v", result, expect)
				}
			case "stream_error":
				if err == nil || !strings.Contains(err.Error(), expect.ErrorCode) {
					t.Fatalf("expected stream error %q, got %v", expect.ErrorCode, err)
				}
			case "interrupted":
				if err == nil || !strings.Contains(err.Error(), "before a terminal event") {
					t.Fatalf("expected interruption error, got %v", err)
				}
			case "invalid":
				if err == nil {
					t.Fatalf("expected a protocol violation error, got result %+v", result)
				}
			default:
				t.Fatalf("unknown vector kind %q", expect.Kind)
			}
		})
	}
}
