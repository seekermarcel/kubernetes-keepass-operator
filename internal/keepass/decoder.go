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
	"bytes"
	"fmt"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

// Database represents an opened and decrypted KeePass database
type Database struct {
	db *gokeepasslib.Database
}

// OpenDatabase opens and decrypts a KeePass database from raw bytes
func OpenDatabase(data []byte, password string) (*Database, error) {
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)

	reader := bytes.NewReader(data)
	if err := gokeepasslib.NewDecoder(reader).Decode(db); err != nil {
		return nil, fmt.Errorf("failed to decode KeePass database: %w", err)
	}

	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("failed to unlock protected entries: %w", err)
	}

	return &Database{db: db}, nil
}

// OpenDatabaseFromFile opens and decrypts a KeePass database from a file path
func OpenDatabaseFromFile(path string, password string) (*Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read KeePass file: %w", err)
	}
	return OpenDatabase(data, password)
}

// GetRootGroup returns the root group of the database
func (d *Database) GetRootGroup() *gokeepasslib.Group {
	if d.db.Content != nil && d.db.Content.Root != nil && len(d.db.Content.Root.Groups) > 0 {
		return &d.db.Content.Root.Groups[0]
	}
	return nil
}

// FindEntryByTitle searches for an entry with the given title in all groups
// Returns the password of the first matching entry
func (d *Database) FindEntryByTitle(title string) (string, bool) {
	root := d.GetRootGroup()
	if root == nil {
		return "", false
	}
	return findEntryInGroup(root, title)
}

// findEntryInGroup recursively searches for an entry by title
func findEntryInGroup(group *gokeepasslib.Group, title string) (string, bool) {
	for _, entry := range group.Entries {
		if getEntryTitle(&entry) == title {
			return getEntryPassword(&entry), true
		}
	}

	for i := range group.Groups {
		if password, found := findEntryInGroup(&group.Groups[i], title); found {
			return password, true
		}
	}

	return "", false
}

// getEntryTitle extracts the title from a KeePass entry
func getEntryTitle(entry *gokeepasslib.Entry) string {
	return entry.GetTitle()
}

// getEntryPassword extracts the password from a KeePass entry
func getEntryPassword(entry *gokeepasslib.Entry) string {
	return entry.GetPassword()
}

// getEntryUsername extracts the username from a KeePass entry
func getEntryUsername(entry *gokeepasslib.Entry) string {
	for _, v := range entry.Values {
		if v.Key == "UserName" {
			return v.Value.Content
		}
	}
	return ""
}
