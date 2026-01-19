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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
)

const (
	// MaxSecretKeyLength is the maximum length for a Kubernetes secret key
	MaxSecretKeyLength = 253
)

// SecretData represents extracted secret data from a KeePass entry
type SecretData struct {
	Key   string
	Value []byte
}

// GroupedSecrets holds secrets grouped by their target secret name
type GroupedSecrets struct {
	// SecretName is the name of the target Kubernetes Secret
	SecretName string
	// Labels are additional labels for the Secret
	Labels map[string]string
	// Data contains the secret key-value pairs
	Data []SecretData
}

// ExtractSecrets extracts all secrets from the database
// It returns secrets grouped by their target secret name based on group configuration
func (d *Database) ExtractSecrets(defaultSecretName string) ([]GroupedSecrets, error) {
	root := d.GetRootGroup()
	if root == nil {
		return nil, fmt.Errorf("database has no root group")
	}

	// Map to collect secrets by target secret name
	secretsMap := make(map[string]*GroupedSecrets)

	// Process all groups
	d.processGroup(root, defaultSecretName, secretsMap)

	// Convert map to slice
	result := make([]GroupedSecrets, 0, len(secretsMap))
	for _, gs := range secretsMap {
		result = append(result, *gs)
	}

	return result, nil
}

// processGroup recursively processes a group and its subgroups
func (d *Database) processGroup(group *gokeepasslib.Group, defaultSecretName string, secretsMap map[string]*GroupedSecrets) {
	// Determine target secret name from group config or use default
	config := ParseGroupConfig(group.Notes)
	targetName := defaultSecretName
	var labels map[string]string

	if config != nil && config.SecretName != "" {
		targetName = config.SecretName
		labels = config.Labels
	}

	// Ensure the target exists in the map
	if _, exists := secretsMap[targetName]; !exists {
		secretsMap[targetName] = &GroupedSecrets{
			SecretName: targetName,
			Labels:     labels,
			Data:       []SecretData{},
		}
	}

	// Process entries in this group
	for i := range group.Entries {
		secrets := d.extractEntrySecrets(&group.Entries[i])
		secretsMap[targetName].Data = append(secretsMap[targetName].Data, secrets...)
	}

	// Process subgroups recursively
	for i := range group.Groups {
		d.processGroup(&group.Groups[i], defaultSecretName, secretsMap)
	}
}

// extractEntrySecrets extracts secret data from a single entry
func (d *Database) extractEntrySecrets(entry *gokeepasslib.Entry) []SecretData {
	var secrets []SecretData
	title := getEntryTitle(entry)
	password := getEntryPassword(entry)
	username := getEntryUsername(entry)

	// Case 1: Entry has a password - store password as secret value
	if password != "" {
		secrets = append(secrets, SecretData{
			Key:   truncateKeyName(title),
			Value: []byte(password),
		})
		return secrets
	}

	// Case 2: Entry has no password but has attachments
	// Only process attachments if both username and password are empty
	if username == "" && password == "" && len(entry.Binaries) > 0 {
		for i := range entry.Binaries {
			binary := &entry.Binaries[i]
			keyName := fmt.Sprintf("%s-%s", title, binary.Name)
			content := d.getBinaryContent(binary)
			if content != nil {
				secrets = append(secrets, SecretData{
					Key:   truncateKeyName(keyName),
					Value: content,
				})
			}
		}
		return secrets
	}

	// Case 3: Entry with empty password - store empty string
	secrets = append(secrets, SecretData{
		Key:   truncateKeyName(title),
		Value: []byte(""),
	})

	return secrets
}

// getBinaryContent retrieves the binary content of an attachment from the database's binary pool
func (d *Database) getBinaryContent(binaryRef *gokeepasslib.BinaryReference) []byte {
	if d.db.Content == nil || d.db.Content.Meta == nil {
		return nil
	}

	// In KDBX 4, binaries are stored in the inner header
	// In KDBX 3.1 and earlier, they're in Meta.Binaries
	binaries := d.db.Content.Meta.Binaries

	// The BinaryReference.Value.ID contains the index into the binaries pool
	if binaryRef.Value.ID >= 0 && binaryRef.Value.ID < len(binaries) {
		binary := binaries[binaryRef.Value.ID]
		return binary.Content
	}

	return nil
}

// truncateKeyName truncates a key name if it exceeds the maximum length
// Uses a deterministic hash-based truncation to ensure consistency
func truncateKeyName(name string) string {
	if len(name) <= MaxSecretKeyLength {
		return name
	}

	// Calculate hash of the original name for determinism
	hash := sha256.Sum256([]byte(name))
	hashStr := hex.EncodeToString(hash[:4]) // 8 character hash

	// Calculate how much space we have for prefix and suffix
	// Format: prefix-{8-char-hash}-suffix
	overhead := len("-") + len(hashStr) + len("-")
	remainingSpace := MaxSecretKeyLength - overhead

	// Split remaining space between prefix and suffix
	prefixLen := remainingSpace / 2
	suffixLen := remainingSpace - prefixLen

	prefix := name[:prefixLen]
	suffix := name[len(name)-suffixLen:]

	truncated := fmt.Sprintf("%s-%s-%s", prefix, hashStr, suffix)

	return truncated
}

// SanitizeSecretKey sanitizes a key name for use in Kubernetes secrets
// Kubernetes secret keys must consist of alphanumeric characters, '-', '_' or '.'
func SanitizeSecretKey(key string) string {
	var result strings.Builder
	for _, r := range key {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' {
			result.WriteRune(r)
		} else {
			result.WriteRune('-')
		}
	}
	return result.String()
}
