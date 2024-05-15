package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedAPIKey string
		expectedError  error
	}{
		{
			name:           "Valid API key",
			headers:        http.Header{"Authorization": {"ApiKey 12345"}},
			expectedAPIKey: "12345",
			expectedError:  nil,
		},
		{
			name:           "Missing authorization header",
			headers:        http.Header{},
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
		{
			name:           "Malformed authorization header - no space",
			headers:        http.Header{"Authorization": {"ApiKey12345"}},
			expectedAPIKey: "",
			expectedError:  ErrMalformedAuthHeader,
		},
		{
			name:           "Malformed authorization header - wrong scheme",
			headers:        http.Header{"Authorization": {"Bearer 12345"}},
			expectedAPIKey: "",
			expectedError:  ErrMalformedAuthHeader,
		},
		// {
		// 	name:           "Malformed authorization header - missing key",
		// 	headers:        http.Header{"Authorization": {"ApiKey "}},
		// 	expectedAPIKey: "",
		// 	expectedError:  ErrMalformedAuthHeader,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if !reflect.DeepEqual(apiKey, tt.expectedAPIKey) {
				t.Fatalf("expected: %s, got: %s", tt.expectedAPIKey, apiKey)
			}
			if err != nil || tt.expectedError != nil {
				if !errors.Is(err, tt.expectedError) {
					t.Fatalf("expected error: %v, got: %v", tt.expectedError, err)
				}
			}
		})
	}
}
