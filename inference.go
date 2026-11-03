package innerva

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Redwood-Labs-US/innerva-client-go/internal/wire"
)

const (
	maximumSSELineBytes     = 1 << 20
	maximumOutputBytes      = 8 << 20
	capabilityRefreshWindow = 30 * time.Second
)

// InferenceResult is the completed, memory-only normalized response. The SDK
// does not persist the input or output and never retries a started stream.
type InferenceResult struct {
	OperationID    string
	Output         string
	Status         string
	InputUnits     int64
	OutputUnits    int64
	CreditsCharged int64
	CreditsCapped  bool
}

// Infer creates one signed streaming inference and collects its text output in
// memory. It refreshes an expiring capability before sending inference bytes and
// never retries a started stream. Callers that need incremental display should
// use the protocol endpoint directly until a callback-based API is added.
func (client *Client) Infer(
	ctx context.Context,
	capability *Capability,
	input string,
	maximumOutputTokens int64,
	idempotencyKey string,
) (InferenceResult, error) {
	if capability == nil || len([]byte(input)) < 1 || len([]byte(input)) > 32768 ||
		maximumOutputTokens < 1 || maximumOutputTokens > 4096 || !validOperationKey(idempotencyKey) {
		return InferenceResult{}, errors.New("invalid inference request")
	}
	currentCapability, err := client.currentCapability(ctx, capability)
	if err != nil {
		return InferenceResult{}, err
	}
	if currentCapability.Value == "" {
		return InferenceResult{}, errors.New("invalid inference request")
	}
	body, err := json.Marshal(wire.InferenceRequest{
		Model: wire.InferenceRequestModelInnervaStandard,
		Input: input, MaxOutputTokens: maximumOutputTokens, Stream: true,
	})
	if err != nil {
		return InferenceResult{}, fmt.Errorf("encode inference request: %w", err)
	}
	endpoint := strings.TrimSuffix(client.baseURL.String(), "/") + "/v1/responses"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return InferenceResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Digest", contentDigest(body))
	request.Header.Set("Authorization", "Innerva "+currentCapability.Value)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	if err := signRequest(request, client.key, client.keyID, client.now()); err != nil {
		return InferenceResult{}, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return InferenceResult{}, fmt.Errorf("call Innerva inference: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return InferenceResult{}, decodeHTTPError(response)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "text/event-stream" {
		return InferenceResult{}, errors.New("innerva returned an invalid inference content type")
	}
	return decodeInferenceStream(response.Body)
}

func (client *Client) currentCapability(ctx context.Context, capability *Capability) (Capability, error) {
	client.refreshMu.Lock()
	if capability.refresh == nil && !capability.ExpiresAt.IsZero() {
		capability.refresh = &sync.Mutex{}
	}
	refresh := capability.refresh
	client.refreshMu.Unlock()
	if refresh == nil {
		return *capability, nil
	}
	refresh.Lock()
	defer refresh.Unlock()
	if client.now().Add(capabilityRefreshWindow).Before(capability.ExpiresAt) {
		return *capability, nil
	}
	refreshed, err := client.Rotate(ctx, *capability)
	if err != nil {
		return Capability{}, fmt.Errorf("refresh inference capability: %w", err)
	}
	refreshed.refresh = refresh
	client.refreshMu.Lock()
	*capability = refreshed
	client.refreshMu.Unlock()
	return refreshed, nil
}

func decodeInferenceStream(reader io.Reader) (InferenceResult, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), maximumSSELineBytes)
	var eventName string
	var dataLines []string
	var result InferenceResult
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			terminal, err := applyInferenceEvent(&result, eventName, strings.Join(dataLines, "\n"))
			if err != nil {
				return InferenceResult{}, err
			}
			if terminal {
				return result, nil
			}
			eventName, dataLines = "", nil
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			return InferenceResult{}, errors.New("innerva returned a malformed inference stream")
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			if eventName != "" {
				return InferenceResult{}, errors.New("innerva returned a malformed inference event")
			}
			eventName = value
		case "data":
			dataLines = append(dataLines, value)
		default:
			return InferenceResult{}, errors.New("innerva returned an unsupported inference event field")
		}
	}
	if err := scanner.Err(); err != nil {
		return InferenceResult{}, fmt.Errorf("read Innerva inference stream: %w", err)
	}
	if eventName != "" || len(dataLines) != 0 {
		terminal, err := applyInferenceEvent(&result, eventName, strings.Join(dataLines, "\n"))
		if err != nil {
			return InferenceResult{}, err
		}
		if terminal {
			return result, nil
		}
	}
	return InferenceResult{}, errors.New("innerva inference stream ended before a terminal event")
}

func applyInferenceEvent(result *InferenceResult, eventName, data string) (bool, error) {
	if eventName == "" || data == "" {
		return false, errors.New("innerva returned an incomplete inference event")
	}
	switch eventName {
	case "response.created":
		var event wire.InferenceCreatedEvent
		if result.OperationID != "" || decodeStrict([]byte(data), &event) != nil ||
			event.Type != wire.ResponseCreated || event.Response.Id == "" ||
			event.Response.Model != wire.InferenceCreatedResponseModelInnervaStandard ||
			event.Response.Status != wire.InProgress {
			return false, errors.New("innerva returned an invalid response.created event")
		}
		result.OperationID = event.Response.Id
		return false, nil
	case "response.output_text.delta":
		var event wire.InferenceDeltaEvent
		if decodeStrict([]byte(data), &event) != nil || result.OperationID == "" ||
			event.Type != wire.ResponseOutputTextDelta || event.ResponseId != result.OperationID ||
			len(result.Output)+len(event.Delta) > maximumOutputBytes {
			return false, errors.New("innerva returned an invalid response delta")
		}
		result.Output += event.Delta
		return false, nil
	case "response.completed", "response.incomplete":
		var event wire.InferenceTerminalEvent
		expectedType, expectedStatus := wire.ResponseCompleted, wire.Completed
		if eventName == "response.incomplete" {
			expectedType, expectedStatus = wire.ResponseIncomplete, wire.Incomplete
		}
		if decodeStrict([]byte(data), &event) != nil || result.OperationID == "" ||
			event.Type != expectedType || event.Response.Id != result.OperationID ||
			event.Response.Status != expectedStatus || event.Response.Usage.InputUnits < 0 ||
			event.Response.Model != wire.InferenceTerminalResponseModelInnervaStandard ||
			event.Response.Usage.OutputUnits < 0 || event.Response.Credits.Charged < 0 ||
			event.Response.Credits.Unit != wire.InferenceCreditsUnitInnervaCredit {
			return false, errors.New("innerva returned an invalid terminal inference event")
		}
		result.Status = string(event.Response.Status)
		result.InputUnits = event.Response.Usage.InputUnits
		result.OutputUnits = event.Response.Usage.OutputUnits
		result.CreditsCharged = event.Response.Credits.Charged
		result.CreditsCapped = event.Response.Credits.Capped
		return true, nil
	case "error":
		var event wire.InferenceErrorEvent
		if decodeStrict([]byte(data), &event) != nil || event.Type != wire.Error || !event.Error.Code.Valid() {
			return false, errors.New("innerva returned an invalid inference error")
		}
		return false, fmt.Errorf("innerva inference %s", event.Error.Code)
	default:
		return false, errors.New("innerva returned an unsupported inference event")
	}
}

func validOperationKey(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
