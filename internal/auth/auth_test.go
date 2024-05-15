package auth

import (
	"errors"
	"net/http"
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
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name:           "Malformed authorization header - wrong scheme",
			headers:        http.Header{"Authorization": {"Bearer 12345"}},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name:           "Malformed authorization header - missing key",
			headers:        http.Header{"Authorization": {"ApiKey "}},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if apiKey != tt.expectedAPIKey {
				t.Errorf("expected %s, got %s", tt.expectedAPIKey, apiKey)
			}
			if (err != nil && tt.expectedError == nil) || (err == nil && tt.expectedError != nil) || (err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}
