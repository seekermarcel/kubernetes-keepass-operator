/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package keepass

import (
	"strings"
	"testing"
)

func TestTruncateKeyName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantLen  int
	}{
		{
			name:     "short name unchanged",
			input:    "my-secret-key",
			expected: "my-secret-key",
			wantLen:  13,
		},
		{
			name:     "empty name",
			input:    "",
			expected: "",
			wantLen:  0,
		},
		{
			name:    "long name truncated",
			input:   strings.Repeat("a", 300),
			wantLen: MaxSecretKeyLength,
		},
		{
			name:    "exactly max length unchanged",
			input:   strings.Repeat("b", MaxSecretKeyLength),
			wantLen: MaxSecretKeyLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateKeyName(tt.input)

			if tt.wantLen > 0 && len(result) != tt.wantLen {
				t.Errorf("truncateKeyName() length = %d, want %d", len(result), tt.wantLen)
			}

			if tt.expected != "" && result != tt.expected {
				t.Errorf("truncateKeyName() = %q, want %q", result, tt.expected)
			}

			// Verify determinism
			result2 := truncateKeyName(tt.input)
			if result != result2 {
				t.Errorf("truncateKeyName() is not deterministic: %q != %q", result, result2)
			}
		})
	}
}

func TestSanitizeSecretKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid key unchanged",
			input:    "my-secret_key.name",
			expected: "my-secret_key.name",
		},
		{
			name:     "spaces replaced",
			input:    "my secret key",
			expected: "my-secret-key",
		},
		{
			name:     "special chars replaced",
			input:    "key@with#special!chars",
			expected: "key-with-special-chars",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only special chars",
			input:    "@#$%^&*()",
			expected: "---------",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeSecretKey(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeSecretKey() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestParseGroupConfig(t *testing.T) {
	tests := []struct {
		name           string
		notes          string
		wantSecretName string
		wantLabels     map[string]string
		wantNil        bool
	}{
		{
			name:    "empty notes",
			notes:   "",
			wantNil: true,
		},
		{
			name:    "whitespace only",
			notes:   "   \n\t  ",
			wantNil: true,
		},
		{
			name:    "invalid JSON",
			notes:   "not valid json",
			wantNil: true,
		},
		{
			name:           "valid config with secret name only",
			notes:          `{"secret-name": "my-secret"}`,
			wantSecretName: "my-secret",
			wantLabels:     nil,
		},
		{
			name:           "valid config with labels",
			notes:          `{"secret-name": "db-creds", "labels": {"type": "database", "env": "prod"}}`,
			wantSecretName: "db-creds",
			wantLabels:     map[string]string{"type": "database", "env": "prod"},
		},
		{
			name:    "invalid secret name",
			notes:   `{"secret-name": "INVALID_NAME"}`,
			wantNil: true,
		},
		{
			name:           "valid secret name with subdomain",
			notes:          `{"secret-name": "my-app.secrets"}`,
			wantSecretName: "my-app.secrets",
			wantLabels:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseGroupConfig(tt.notes)

			if tt.wantNil {
				if result != nil {
					t.Errorf("ParseGroupConfig() = %+v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatalf("ParseGroupConfig() = nil, want non-nil")
			}

			if result.SecretName != tt.wantSecretName {
				t.Errorf("ParseGroupConfig().SecretName = %q, want %q", result.SecretName, tt.wantSecretName)
			}

			if tt.wantLabels != nil {
				if len(result.Labels) != len(tt.wantLabels) {
					t.Errorf("ParseGroupConfig().Labels length = %d, want %d", len(result.Labels), len(tt.wantLabels))
				}
				for k, v := range tt.wantLabels {
					if result.Labels[k] != v {
						t.Errorf("ParseGroupConfig().Labels[%q] = %q, want %q", k, result.Labels[k], v)
					}
				}
			}
		})
	}
}

func TestValidateLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{
			name:   "nil labels",
			labels: nil,
			want:   true,
		},
		{
			name:   "empty labels",
			labels: map[string]string{},
			want:   true,
		},
		{
			name:   "valid simple labels",
			labels: map[string]string{"app": "myapp", "env": "prod"},
			want:   true,
		},
		{
			name:   "valid label with prefix",
			labels: map[string]string{"app.kubernetes.io/name": "myapp"},
			want:   true,
		},
		{
			name:   "empty label value allowed",
			labels: map[string]string{"app": ""},
			want:   true,
		},
		{
			name:   "invalid empty key",
			labels: map[string]string{"": "value"},
			want:   false,
		},
		{
			name:   "invalid value too long",
			labels: map[string]string{"key": strings.Repeat("a", 64)},
			want:   false,
		},
		{
			name:   "invalid key too long",
			labels: map[string]string{strings.Repeat("a", 64): "value"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateLabels(tt.labels)
			if result != tt.want {
				t.Errorf("ValidateLabels() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestIsValidSecretName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid simple name",
			input: "my-secret",
			want:  true,
		},
		{
			name:  "valid with dots",
			input: "my.secret.name",
			want:  true,
		},
		{
			name:  "valid single char",
			input: "a",
			want:  true,
		},
		{
			name:  "invalid uppercase",
			input: "MySecret",
			want:  false,
		},
		{
			name:  "invalid starts with hyphen",
			input: "-mysecret",
			want:  false,
		},
		{
			name:  "invalid ends with hyphen",
			input: "mysecret-",
			want:  false,
		},
		{
			name:  "invalid empty",
			input: "",
			want:  false,
		},
		{
			name:  "invalid too long",
			input: strings.Repeat("a", 254),
			want:  false,
		},
		{
			name:  "valid max length",
			input: strings.Repeat("a", 253),
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSecretName(tt.input)
			if result != tt.want {
				t.Errorf("isValidSecretName(%q) = %v, want %v", tt.input, result, tt.want)
			}
		})
	}
}
