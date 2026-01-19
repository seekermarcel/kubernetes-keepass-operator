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
	"encoding/json"
	"regexp"
	"strings"
)

// GroupConfig represents the configuration parsed from a KeePass group's notes field
type GroupConfig struct {
	// SecretName is the target Kubernetes secret name
	SecretName string `json:"secret-name"`
	// Labels are additional labels to apply to the generated secret
	Labels map[string]string `json:"labels,omitempty"`
}

// ParseGroupConfig parses a GroupConfig from the group notes field
// Returns nil if the notes are empty or not valid JSON
func ParseGroupConfig(notes string) *GroupConfig {
	notes = strings.TrimSpace(notes)
	if notes == "" {
		return nil
	}

	var config GroupConfig
	if err := json.Unmarshal([]byte(notes), &config); err != nil {
		// Not valid JSON, return nil and use default behavior
		return nil
	}

	// Validate secret name if provided
	if config.SecretName != "" && !isValidSecretName(config.SecretName) {
		return nil
	}

	// Validate labels if provided
	if config.Labels != nil && !ValidateLabels(config.Labels) {
		// Invalid labels, clear them but keep the secret name
		config.Labels = nil
	}

	return &config
}

// isValidSecretName validates a Kubernetes secret name
// Must be lowercase, max 253 chars, alphanumeric/hyphens/dots, RFC 1123 compliant
func isValidSecretName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}

	// RFC 1123 DNS subdomain name pattern
	pattern := `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	matched, _ := regexp.MatchString(pattern, name)
	return matched
}

// ValidateLabels validates Kubernetes labels
// Label keys: max 63 chars name, optional 253 char prefix, alphanumeric/hyphens/underscores/dots
// Label values: max 63 chars, alphanumeric/hyphens/underscores/dots, can be empty
func ValidateLabels(labels map[string]string) bool {
	for key, value := range labels {
		if !isValidLabelKey(key) || !isValidLabelValue(value) {
			return false
		}
	}
	return true
}

// isValidLabelKey validates a Kubernetes label key
func isValidLabelKey(key string) bool {
	if key == "" {
		return false
	}

	// Check for prefix/name format
	parts := strings.Split(key, "/")
	var name string
	var prefix string

	switch len(parts) {
	case 1:
		name = parts[0]
	case 2:
		prefix = parts[0]
		name = parts[1]
	default:
		return false
	}

	// Validate prefix if present (max 253 chars, DNS subdomain)
	if prefix != "" {
		if len(prefix) > 253 {
			return false
		}
		if !isValidSecretName(prefix) {
			return false
		}
	}

	// Validate name (max 63 chars)
	if len(name) == 0 || len(name) > 63 {
		return false
	}

	// Name must start and end with alphanumeric
	namePattern := `^[a-zA-Z0-9]([-_.a-zA-Z0-9]*[a-zA-Z0-9])?$`
	matched, _ := regexp.MatchString(namePattern, name)
	return matched
}

// isValidLabelValue validates a Kubernetes label value
func isValidLabelValue(value string) bool {
	// Empty value is allowed
	if value == "" {
		return true
	}

	// Max 63 chars
	if len(value) > 63 {
		return false
	}

	// Must start and end with alphanumeric, can contain alphanumeric, hyphens, underscores, dots
	pattern := `^[a-zA-Z0-9]([-_.a-zA-Z0-9]*[a-zA-Z0-9])?$`
	matched, _ := regexp.MatchString(pattern, value)
	return matched
}
