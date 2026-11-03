package innerva

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	signatureInputPattern = regexp.MustCompile(
		`^sig1=\(("[a-z@-]+"(?: "[a-z@-]+")*)\);created=([0-9]+);expires=([0-9]+);keyid="([A-Za-z0-9_-]+)";alg="ecdsa-p256-sha256"$`,
	)
	signaturePattern = regexp.MustCompile(`^sig1=:([A-Za-z0-9+/]+={0,2}):$`)
	noncePattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

// verifyProof is a test-only verifier for the v0.1 proof profile. It rebuilds
// the signature base from the received request rather than from signer
// internals, applies the server's structural rules (required components,
// lifetime, clock skew, key binding, nonce shape, body digest), and checks the
// ES256 signature. The shared conformance vectors pin the same bytes to the
// server's own verifier.
func verifyProof(t *testing.T, request *http.Request, body []byte, key *ecdsa.PublicKey, keyID string, now time.Time) {
	t.Helper()
	if digest := request.Header.Get("Content-Digest"); digest != "" {
		sum := sha256.Sum256(body)
		if digest != "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":" {
			t.Errorf("Content-Digest %q does not match the body", digest)
		}
	}
	if !noncePattern.MatchString(request.Header.Get("Innerva-Nonce")) {
		t.Errorf("Innerva-Nonce %q is malformed", request.Header.Get("Innerva-Nonce"))
	}
	input := signatureInputPattern.FindStringSubmatch(request.Header.Get("Signature-Input"))
	if input == nil {
		t.Errorf("Signature-Input %q is malformed", request.Header.Get("Signature-Input"))
		return
	}
	created, _ := strconv.ParseInt(input[2], 10, 64)
	expires, _ := strconv.ParseInt(input[3], 10, 64)
	if input[4] != keyID {
		t.Errorf("keyid %q does not match the proof key %q", input[4], keyID)
	}
	if skew := now.Unix() - created; skew > 60 || skew < -60 {
		t.Errorf("created %d is outside the clock skew around %d", created, now.Unix())
	}
	if expires <= now.Unix() || expires <= created || expires-created > 60 {
		t.Errorf("expires %d is outside the allowed lifetime (created %d)", expires, created)
	}
	var components []string
	for _, quoted := range strings.Split(input[1], " ") {
		components = append(components, strings.Trim(quoted, `"`))
	}
	required := []string{"@method", "@target-uri", "innerva-nonce"}
	if request.Header.Get("Content-Digest") != "" {
		required = append(required, "content-digest", "content-type")
	}
	if request.Header.Get("Authorization") != "" {
		required = append(required, "authorization")
	}
	if request.Header.Get("Idempotency-Key") != "" {
		required = append(required, "idempotency-key")
	}
	for _, name := range required {
		if !strings.Contains(input[1], `"`+name+`"`) {
			t.Errorf("signature does not cover %q", name)
		}
	}
	lines := make([]string, 0, len(components)+1)
	for _, name := range components {
		var value string
		switch name {
		case "@method":
			value = request.Method
		case "@target-uri":
			value = request.URL.String()
		default:
			value = request.Header.Get(name)
		}
		lines = append(lines, `"`+name+`": `+value)
	}
	lines = append(lines, `"@signature-params": `+strings.TrimPrefix(request.Header.Get("Signature-Input"), "sig1="))
	signature := signaturePattern.FindStringSubmatch(request.Header.Get("Signature"))
	if signature == nil {
		t.Errorf("Signature %q is malformed", request.Header.Get("Signature"))
		return
	}
	if !verifyES256(key, strings.Join(lines, "\n"), signature[1]) {
		t.Error("signature does not verify over the reconstructed signature base")
	}
}

// verifyES256 checks a base64 raw r||s ES256 signature over base.
func verifyES256(key *ecdsa.PublicKey, base, encoded string) bool {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(base))
	return ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]))
}

func testKeyID(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	jwk, err := jwkFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := jwkThumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	return thumbprint
}
