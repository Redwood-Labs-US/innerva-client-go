// Package innerva is the Go server SDK for the Innerva Grant Protocol (IGP)
// v0.1: it signs protocol requests with a durable P-256 proof key, runs the
// access-request and browser-interaction flow, and streams normalized
// inference against an Innerva deployment. It depends only on the standard
// library.
//
// The API reference is https://innerva.net/docs/api and the machine-readable
// contract is served by every deployment at /openapi.yaml.
package innerva

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Redwood-Labs-US/innerva-client-go/internal/wire"
)

const maxResponseBody = 1 << 20

// Config identifies one developer integration environment.
type Config struct {
	BaseURL      string
	ProofKeyPath string
	DisplayName  string
	DisplayURI   string
	CallbackURI  string
	// HTTPClient optionally supplies transport behavior. Its Timeout, when set,
	// also applies to inference streams; otherwise Infer follows its context.
	HTTPClient *http.Client
	// SpendAuthorization is an operator-issued staging credential sent with
	// every access request. Non-production Innerva environments use it to let
	// this integration's grants consume real model inference; leave it empty
	// against production, which ignores the header.
	SpendAuthorization string
}

// RequestOptions customizes one access request without exposing fulfillment choices.
type RequestOptions struct {
	SuggestedCredits *int64
	MinimumCredits   *int64
	ClientReference  string
	CallbackURI      string
	IdempotencyKey   string
}

// PendingAccess is the durable state needed to finish one browser interaction.
type PendingAccess struct {
	RequestID         string
	InstanceID        string
	InteractionURI    string
	ContinuationURI   string
	ContinuationToken string
	ClientFinish      string
	ServerFinish      string
	AccessEndpoint    string
}

// Capability is an opaque inference credential plus its lifecycle authority.
// Keep it protected and pass the same pointer to Infer so the SDK can replace
// an expiring inference token before starting a request.
type Capability struct {
	Value           string
	ManagementToken string
	ManagementURI   string
	CapabilityID    string
	GrantID         string
	GrantLimit      int64
	GrantRemaining  int64
	ExpiresIn       time.Duration
	ExpiresAt       time.Time
	refresh         *sync.Mutex
}

// Client signs protocol requests with one durable integration key.
type Client struct {
	baseURL            *url.URL
	key                *ecdsa.PrivateKey
	keyID              string
	publicJWK          publicJWK
	displayName        string
	displayURI         string
	callbackURI        string
	httpClient         *http.Client
	spendAuthorization string
	requestTimeout     time.Duration
	refreshMu          sync.Mutex
	now                func() time.Time
}

// KeyThumbprint identifies this integration's proof key. Operators use it to
// issue credentials bound to the key, such as staging spend authorizations.
func (client *Client) KeyThumbprint() string { return client.keyID }

// Open loads or creates the configured proof key and returns a ready client.
func Open(configuration Config) (*Client, error) {
	key, err := LoadOrCreateProofKey(configuration.ProofKeyPath)
	if err != nil {
		return nil, err
	}
	return New(configuration, key)
}

// New creates a client around an already managed P-256 key.
func New(configuration Config, key *ecdsa.PrivateKey) (*Client, error) {
	if key == nil {
		return nil, errors.New("proof key is required")
	}
	baseURL, err := parseAbsoluteURL(configuration.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("base URL: %w", err)
	}
	if (baseURL.Path != "" && baseURL.Path != "/") || baseURL.RawQuery != "" {
		return nil, errors.New("base URL must be an origin without a path or query")
	}
	if baseURL.Scheme != "https" && !isLoopbackHost(baseURL.Hostname()) {
		return nil, errors.New("base URL must use HTTPS outside loopback development")
	}
	// The server verifies signatures against its canonical origin, so sign
	// and compare using the same normalized authority whatever the caller
	// wrote (upper-case host, explicit default port).
	baseURL.Host = normalizedAuthority(baseURL)
	if configuration.DisplayName == "" || len(configuration.DisplayName) > 120 {
		return nil, errors.New("display name must be 1 to 120 characters")
	}
	if _, err := parseAbsoluteURL(configuration.DisplayURI); err != nil {
		return nil, fmt.Errorf("display URI: %w", err)
	}
	if _, err := parseAbsoluteURL(configuration.CallbackURI); err != nil {
		return nil, fmt.Errorf("callback URI: %w", err)
	}
	jwk, err := jwkFromPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	keyID, err := jwkThumbprint(jwk)
	if err != nil {
		return nil, err
	}
	httpClient := configuration.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	clientCopy := *httpClient
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		baseURL: baseURL, key: key, keyID: keyID, publicJWK: jwk,
		displayName: configuration.DisplayName, displayURI: configuration.DisplayURI,
		callbackURI: configuration.CallbackURI, httpClient: &clientCopy,
		spendAuthorization: configuration.SpendAuthorization,
		requestTimeout:     15 * time.Second,
		now:                func() time.Time { return time.Now().UTC() },
	}, nil
}

// CreateAccess starts a signed access request and returns its browser interaction.
func (client *Client) CreateAccess(ctx context.Context, options RequestOptions) (PendingAccess, error) {
	callbackURI := client.callbackURI
	if options.CallbackURI != "" {
		if _, err := parseAbsoluteURL(options.CallbackURI); err != nil {
			return PendingAccess{}, fmt.Errorf("callback URI: %w", err)
		}
		callbackURI = options.CallbackURI
	}
	clientFinish, err := newToken("cf1_")
	if err != nil {
		return PendingAccess{}, err
	}
	accessRequest := newAccessRequest(client, options, callbackURI, clientFinish)
	var created wire.AccessRequestCreated
	accessEndpoint := strings.TrimSuffix(client.baseURL.String(), "/") + "/v1/access-requests"
	var extraHeaders [][2]string
	if client.spendAuthorization != "" {
		extraHeaders = append(extraHeaders, [2]string{spendAuthorizationHeader, client.spendAuthorization})
	}
	if err := client.postJSON(ctx, accessEndpoint, accessRequest, "", options.IdempotencyKey, &created, extraHeaders...); err != nil {
		return PendingAccess{}, err
	}
	if created.ProtocolVersion != wire.N01 || created.RequestId == "" || created.InstanceId == "" ||
		created.Continue.Uri == "" || created.Continue.AccessToken.Value == "" || created.Interact.Redirect == "" {
		return PendingAccess{}, errors.New("innerva returned an incomplete access response")
	}
	if err := client.requireSameOrigin(created.Continue.Uri); err != nil {
		return PendingAccess{}, fmt.Errorf("continuation URI: %w", err)
	}
	if err := client.requireSameOrigin(created.Interact.Redirect); err != nil {
		return PendingAccess{}, fmt.Errorf("interaction URI: %w", err)
	}
	return PendingAccess{
		RequestID: created.RequestId, InstanceID: created.InstanceId,
		InteractionURI: created.Interact.Redirect, ContinuationURI: created.Continue.Uri,
		ContinuationToken: created.Continue.AccessToken.Value, ClientFinish: clientFinish,
		ServerFinish: created.Interact.Finish, AccessEndpoint: accessEndpoint,
	}, nil
}

// ValidateCallback verifies that the browser result belongs to pending.
func (client *Client) ValidateCallback(pending PendingAccess, interactReference, callbackHash string) bool {
	expected := interactionHash(
		pending.ClientFinish, pending.ServerFinish, interactReference, pending.AccessEndpoint,
	)
	return len(expected) == len(callbackHash) && subtle.ConstantTimeCompare([]byte(expected), []byte(callbackHash)) == 1
}

// Continue validates the browser binding and exchanges it for an inference capability.
func (client *Client) Continue(
	ctx context.Context,
	pending PendingAccess,
	interactReference, callbackHash string,
) (Capability, error) {
	if !client.ValidateCallback(pending, interactReference, callbackHash) {
		return Capability{}, errors.New("interaction callback binding is invalid")
	}
	var response wire.CapabilityResponse
	if err := client.postJSON(
		ctx,
		pending.ContinuationURI,
		wire.ContinuationRequest{InteractRef: interactReference},
		pending.ContinuationToken,
		operationIdempotencyKey("continue-", pending.ContinuationToken),
		&response,
	); err != nil {
		return Capability{}, err
	}
	return client.acceptCapability(response)
}

// Rotate replaces the short-lived inference token using the management credential.
func (client *Client) Rotate(ctx context.Context, capability Capability) (Capability, error) {
	endpoint := strings.TrimSuffix(capability.ManagementURI, "/") + "/rotate"
	if err := client.requireSameOrigin(endpoint); err != nil {
		return Capability{}, err
	}
	var response wire.CapabilityResponse
	if err := client.postJSON(
		ctx, endpoint, map[string]any{}, capability.ManagementToken,
		operationIdempotencyKey("rotate-", capability.Value), &response,
	); err != nil {
		return Capability{}, err
	}
	return client.acceptCapability(response)
}

// Revoke immediately revokes the capability and its sandbox grant.
func (client *Client) Revoke(ctx context.Context, capability Capability) error {
	if err := client.requireSameOrigin(capability.ManagementURI); err != nil {
		return err
	}
	requestContext, cancel := context.WithTimeout(ctx, client.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodDelete, capability.ManagementURI, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Innerva "+capability.ManagementToken)
	if err := signRequest(request, client.key, client.keyID, client.now()); err != nil {
		return err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("revoke capability: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent {
		return decodeHTTPError(response)
	}
	return nil
}

func newAccessRequest(client *Client, options RequestOptions, callbackURI, clientFinish string) wire.AccessRequest {
	request := wire.AccessRequest{ProtocolVersion: "0.1"}
	request.Client.Key.Proof = wire.RequestClientKeyProofHttpsig
	request.Client.Key.Jwk = wire.PublicJWK{
		Kty: wire.EC, Crv: wire.P256,
		X: client.publicJWK.X, Y: client.publicJWK.Y,
	}
	request.Client.Display.Name = client.displayName
	request.Client.Display.Uri = client.displayURI
	requested := wire.RequestedAccess{
		Type:     wire.RequestedAccessTypeInnervaInference,
		Actions:  []wire.RequestedAccessActions{wire.RequestedAccessActionsResponsesCreate},
		Models:   []wire.RequestedAccessModels{wire.RequestedAccessModelsInnervaStandard},
		Duration: wire.UntilDepletedOrRevoked,
		Credits:  wire.RequestedCredits{Unit: wire.RequestedCreditsUnitInnervaCredit},
	}
	requested.Credits.Suggested = options.SuggestedCredits
	requested.Credits.Minimum = options.MinimumCredits
	request.AccessToken.Access = []wire.RequestedAccess{requested}
	request.Interact.Start = []wire.RequestedInteractionStart{wire.Redirect}
	request.Interact.Finish.Method = wire.RequestedInteractionFinishMethodRedirect
	request.Interact.Finish.Uri = callbackURI
	request.Interact.Finish.Nonce = clientFinish
	request.Interact.Finish.HashMethod = wire.Sha256
	if options.ClientReference != "" {
		request.ClientReference = &options.ClientReference
	}
	return request
}

func (client *Client) postJSON(
	ctx context.Context,
	endpoint string,
	body any,
	token, idempotencyKey string,
	destination any,
	extraHeaders ...[2]string,
) error {
	if err := client.requireSameOrigin(endpoint); err != nil {
		return err
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode Innerva request: %w", err)
	}
	requestContext, cancel := context.WithTimeout(ctx, client.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Digest", contentDigest(encoded))
	if token != "" {
		request.Header.Set("Authorization", "Innerva "+token)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	for _, header := range extraHeaders {
		request.Header.Set(header[0], header[1])
	}
	if err := signRequest(request, client.key, client.keyID, client.now()); err != nil {
		return err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call Innerva: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decodeHTTPError(response)
	}
	limited := io.LimitReader(response.Body, maxResponseBody+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read Innerva response: %w", err)
	}
	if len(responseBody) > maxResponseBody {
		return errors.New("innerva response is too large")
	}
	if err := decodeStrict(responseBody, destination); err != nil {
		return fmt.Errorf("decode Innerva response: %w", err)
	}
	return nil
}

func decodeHTTPError(response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, maxResponseBody))
	var problem wire.Problem
	if err := json.Unmarshal(body, &problem); err == nil && problem.Code != "" {
		return fmt.Errorf("innerva %s (%d): %s", problem.Code, response.StatusCode, problem.Title)
	}
	return fmt.Errorf("innerva request failed with HTTP %d", response.StatusCode)
}

func (client *Client) mapCapability(response wire.CapabilityResponse) (Capability, error) {
	token := response.AccessToken
	if token.Value == "" || token.Manage.AccessToken.Value == "" || token.Manage.Uri == "" || len(token.Access) != 1 {
		return Capability{}, errors.New("innerva returned an incomplete capability")
	}
	granted := token.Access[0]
	managementURI := token.Manage.Uri
	parts := strings.Split(strings.TrimSuffix(managementURI, "/"), "/")
	capabilityID := parts[len(parts)-1]
	expiresIn := time.Duration(token.ExpiresIn) * time.Second
	return Capability{
		Value: token.Value, ManagementToken: token.Manage.AccessToken.Value,
		ManagementURI: managementURI, CapabilityID: capabilityID, GrantID: granted.GrantId,
		GrantLimit: granted.Credits.GrantLimit, GrantRemaining: granted.Credits.GrantRemaining,
		ExpiresIn: expiresIn, ExpiresAt: client.now().Add(expiresIn), refresh: &sync.Mutex{},
	}, nil
}

func (client *Client) acceptCapability(response wire.CapabilityResponse) (Capability, error) {
	if response.AccessToken.Key.Jkt != client.keyID {
		return Capability{}, errors.New("innerva capability is bound to an unexpected proof key")
	}
	capability, err := client.mapCapability(response)
	if err != nil {
		return Capability{}, err
	}
	if err := client.requireSameOrigin(capability.ManagementURI); err != nil {
		return Capability{}, fmt.Errorf("management URI: %w", err)
	}
	return capability, nil
}

func operationIdempotencyKey(prefix, credential string) string {
	digest := sha256.Sum256([]byte(credential))
	return prefix + hex.EncodeToString(digest[:])
}

func (client *Client) requireSameOrigin(value string) error {
	parsed, err := parseAbsoluteURL(value)
	if err != nil {
		return err
	}
	if parsed.Scheme != client.baseURL.Scheme || normalizedAuthority(parsed) != client.baseURL.Host {
		return errors.New("innerva endpoint origin does not match the configured base URL")
	}
	return nil
}

func parseAbsoluteURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("must be an absolute HTTP(S) URL without credentials or fragment")
	}
	return parsed, nil
}

// normalizedAuthority returns the URL's host lower-cased, with the port kept
// only when it is not the scheme's default, matching the canonical origin a
// server derives for the same URL.
func normalizedAuthority(parsed *url.URL) string {
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
