package innerva

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// decodeStrict rejects duplicate fields, unknown fields, and trailing JSON, the
// same strict profile the Innerva server applies to what it receives.
func decodeStrict(data []byte, destination any) error {
	if destination == nil {
		return errors.New("JSON destination is required")
	}
	duplicateDecoder := json.NewDecoder(bytes.NewReader(data))
	duplicateDecoder.UseNumber()
	if err := readJSONValue(duplicateDecoder); err != nil {
		return err
	}
	if token, err := duplicateDecoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON contains trailing data near %v", token)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func readJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON object name: %w", err)
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("JSON object name is not a string")
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("duplicate JSON field %q", name)
			}
			seen[name] = struct{}{}
			if err := readJSONValue(decoder); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("close JSON object: %w", err)
		}
	case '[':
		for decoder.More() {
			if err := readJSONValue(decoder); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("close JSON array: %w", err)
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
