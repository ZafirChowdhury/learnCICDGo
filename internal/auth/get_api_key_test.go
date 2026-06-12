package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "valid ApiKey header",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		{
			name:       "wrong scheme - Bearer token",
			headers:    http.Header{"Authorization": []string{"Bearer some-token"}},
			wantKey:    "",
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "header value with no space",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:    "",
			wantErrMsg: "malformed authorization header",
		},
		{
			name:    "extra parts are ignored - only second segment returned",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key extra"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.headers)

			// Check returned key
			if gotKey != tc.wantKey {
				t.Errorf("key: got %q, want %q", gotKey, tc.wantKey)
			}

			// Check for a specific sentinel error
			if tc.wantErr != nil {
				if gotErr != tc.wantErr {
					t.Errorf("error: got %v, want %v", gotErr, tc.wantErr)
				}
				return
			}

			// Check for an error by message
			if tc.wantErrMsg != "" {
				if gotErr == nil || gotErr.Error() != tc.wantErrMsg {
					t.Errorf("error message: got %v, want %q", gotErr, tc.wantErrMsg)
				}
				return
			}

			// Expect no error
			if gotErr != nil {
				t.Errorf("unexpected error: %v", gotErr)
			}
		})
	}
}
