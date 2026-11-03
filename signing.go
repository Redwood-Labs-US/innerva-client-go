package innerva

// This file is the client half of the Innerva Grant Protocol v0.1 proof
// profile: RFC 9421 HTTP message signatures (ecdsa-p256-sha256), the RFC 9530
// Content-Digest field, RFC 7638 JWK thumbprints, and the interaction callback
// hash. It depends only on the standard library. The shared conformance vectors
// (conformance/vectors/signing.json and hashing.json) pin every byte it
// produces to what the Innerva server verifies; see conformance_test.go.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	signatureLabel     = "sig1"
	signatureAlgorithm = "ecdsa-p256-sha256"
	// signatureLifetime is the proof lifetime the server accepts at most.
	signatureLifetime = time.Minute
	// tokenEntropyBytes sizes client-generated nonces and finish values.
	tokenEntropyBytes = 32
	// spendAuthorizationHeader carries an operator-issued staging spend
	// authorization on the access request (see Config.SpendAuthorization).
	spendAuthorizationHeader = "Innerva-Staging-Spend-Authorization"
)

var rawURL = base64.RawURLEncoding

// publicJWK is the only proof-key shape IGP v0.1 supports: a public P-256 EC key.
type publicJWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwkFromPublicKey serializes a P-256 key in the public v0.1 JWK shape.
func jwkFromPublicKey(key *ecdsa.PublicKey) (publicJWK, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return publicJWK{}, errors.New("a valid P-256 public key is required")
	}
	// ECDH (not PublicKey.Bytes, which needs Go 1.25) keeps the module's
	// supported Go floor low; both yield the uncompressed SEC 1 point.
	ecdhKey, err := key.ECDH()
	if err != nil {
		return publicJWK{}, errors.New("a valid P-256 public key is required")
	}
	encodedPoint := ecdhKey.Bytes()
	if len(encodedPoint) != 65 || encodedPoint[0] != 4 {
		return publicJWK{}, errors.New("a valid P-256 public key is required")
	}
	return publicJWK{
		KTY: "EC",
		CRV: "P-256",
		X:   rawURL.EncodeToString(encodedPoint[1:33]),
		Y:   rawURL.EncodeToString(encodedPoint[33:]),
	}, nil
}

// jwkThumbprint returns the RFC 7638 SHA-256 thumbprint of a public JWK: the
// base64url digest of its required members in lexicographic order.
func jwkThumbprint(jwk publicJWK) (string, error) {
	canonical, err := json.Marshal(struct {
		CRV string `json:"crv"`
		KTY string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{CRV: jwk.CRV, KTY: jwk.KTY, X: jwk.X, Y: jwk.Y})
	if err != nil {
		return "", fmt.Errorf("marshal canonical JWK: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return rawURL.EncodeToString(digest[:]), nil
}

// contentDigest returns the canonical v0.1 Content-Digest field value: a
// structured-field dictionary with one sha-256 byte sequence.
func contentDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(digest[:]) + ":"
}

// interactionHash binds the browser result to the exact pending request.
func interactionHash(clientFinish, serverFinish, interactReference, endpoint string) string {
	digest := sha256.Sum256([]byte(clientFinish + "\n" + serverFinish + "\n" + interactReference + "\n" + endpoint))
	return rawURL.EncodeToString(digest[:])
}

// newToken creates an opaque, typed value with 256 random bits.
func newToken(prefix string) (string, error) {
	value := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return prefix + rawURL.EncodeToString(value), nil
}

// signRequest adds the v0.1 proof headers (Innerva-Nonce, Signature-Input,
// Signature) to a request whose other headers are already final.
func signRequest(request *http.Request, key *ecdsa.PrivateKey, keyID string, now time.Time) error {
	nonce, err := newToken("n1_")
	if err != nil {
		return err
	}
	return signRequestWithNonce(request, key, keyID, now, nonce)
}

func signRequestWithNonce(request *http.Request, key *ecdsa.PrivateKey, keyID string, now time.Time, nonce string) error {
	if request == nil || request.URL == nil || key == nil || keyID == "" {
		return errors.New("request, private key, and key ID are required")
	}
	request.Header.Set("Innerva-Nonce", nonce)
	components := coveredComponents(request.Header)
	created := now.UTC().Unix()
	parameters := signatureParams(components, created, created+int64(signatureLifetime/time.Second), keyID)
	base, err := signatureBase(request, components, parameters)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(base))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return fmt.Errorf("sign HTTP request: %w", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	request.Header.Set("Signature-Input", signatureLabel+"="+parameters)
	request.Header.Set("Signature", signatureLabel+"=:"+base64.StdEncoding.EncodeToString(signature)+":")
	return nil
}

// coveredComponents is the ordered component list the server requires for a
// request with these headers.
func coveredComponents(header http.Header) []string {
	components := []string{"@method", "@target-uri"}
	if header.Get("Content-Digest") != "" {
		components = append(components, "content-digest", "content-type")
	}
	components = append(components, "innerva-nonce")
	if header.Get("Authorization") != "" {
		components = append(components, "authorization")
	}
	if header.Get("Idempotency-Key") != "" {
		components = append(components, "idempotency-key")
	}
	return components
}

// signatureParams serializes the @signature-params value for the fixed profile.
func signatureParams(components []string, created, expires int64, keyID string) string {
	quoted := make([]string, len(components))
	for index, name := range components {
		quoted[index] = `"` + name + `"`
	}
	return fmt.Sprintf(
		`(%s);created=%d;expires=%d;keyid="%s";alg="%s"`,
		strings.Join(quoted, " "), created, expires, keyID, signatureAlgorithm,
	)
}

// signatureBase builds the RFC 9421 signature base for the covered components.
func signatureBase(request *http.Request, components []string, parameters string) (string, error) {
	lines := make([]string, 0, len(components)+1)
	for _, name := range components {
		var value string
		switch name {
		case "@method":
			value = request.Method
		case "@target-uri":
			value = targetURI(request)
		default:
			values := request.Header.Values(name)
			if len(values) != 1 {
				return "", fmt.Errorf("signed header %q must have exactly one value", name)
			}
			value = values[0]
		}
		if strings.ContainsAny(value, "\r\n") {
			return "", fmt.Errorf("signed component %q contains a line break", name)
		}
		lines = append(lines, `"`+name+`": `+value)
	}
	lines = append(lines, `"@signature-params": `+parameters)
	return strings.Join(lines, "\n"), nil
}

// targetURI derives the RFC 9421 @target-uri of an outgoing request: scheme,
// authority, escaped path (at least "/"), and the raw query when present.
func targetURI(request *http.Request) string {
	authority := request.URL.Host
	if authority == "" {
		authority = request.Host
	}
	path := request.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	target := request.URL.Scheme + "://" + authority + path
	if request.URL.RawQuery != "" {
		target += "?" + request.URL.RawQuery
	}
	return target
}
