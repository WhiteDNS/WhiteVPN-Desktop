package profiles

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"whitevpn-desktop/internal/model"
)

const (
	desktopBackupSchema  = "whitedns.desktop.backup"
	desktopBackupVersion = 1
)

type desktopBackup struct {
	Schema        string               `json:"schema"`
	Version       int                  `json:"version"`
	ExportedAt    string               `json:"exportedAt"`
	State         model.AppState       `json:"state"`
	ResolverFiles []backupResolverFile `json:"resolverFiles,omitempty"`
}

type backupResolverFile struct {
	ProfileID    string `json:"profileId"`
	ResolverText string `json:"resolverText"`
}

func (s *Store) ExportBackup(state model.AppState) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state = NormalizeState(state)
	backup := desktopBackup{
		Schema:     desktopBackupSchema,
		Version:    desktopBackupVersion,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		State:      state,
	}

	for idx, profile := range backup.State.ResolverProfiles {
		if !resolverProfileIsFileBacked(profile) {
			continue
		}

		raw, err := os.ReadFile(profile.ResolverFile)
		if err != nil {
			return "", fmt.Errorf("read resolver profile %q: %w", profile.Name, err)
		}
		backup.ResolverFiles = append(backup.ResolverFiles, backupResolverFile{
			ProfileID:    profile.ID,
			ResolverText: string(raw),
		})
		backup.State.ResolverProfiles[idx].ResolverFile = ""
	}

	raw, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *Store) ImportBackup(rawText string) (model.AppState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rawText = strings.TrimSpace(rawText)
	if rawText == "" {
		return model.AppState{}, fmt.Errorf("backup JSON is required")
	}

	var backup desktopBackup
	if err := json.Unmarshal([]byte(rawText), &backup); err != nil {
		return model.AppState{}, fmt.Errorf("invalid backup JSON")
	}
	if backup.Schema != desktopBackupSchema {
		return model.AppState{}, fmt.Errorf("unsupported backup schema")
	}
	if backup.Version != desktopBackupVersion {
		return model.AppState{}, fmt.Errorf("unsupported backup version")
	}

	state, err := s.restoreBackupResolverFilesLocked(backup)
	if err != nil {
		return model.AppState{}, err
	}
	state.Runtime = model.DefaultAppState().Runtime
	state, _, err = s.prepareStateLocked(state, false)
	if err != nil {
		return model.AppState{}, err
	}
	if err := s.writeStateLocked(state); err != nil {
		return model.AppState{}, err
	}
	return state, nil
}

func (s *Store) restoreBackupResolverFilesLocked(backup desktopBackup) (model.AppState, error) {
	state := backup.State
	resolverTextByID := make(map[string]string, len(backup.ResolverFiles))
	for _, file := range backup.ResolverFiles {
		id := strings.TrimSpace(file.ProfileID)
		if id == "" {
			return model.AppState{}, fmt.Errorf("backup resolver file is missing a profile ID")
		}
		if _, exists := resolverTextByID[id]; exists {
			return model.AppState{}, fmt.Errorf("backup contains duplicate resolver file for %q", id)
		}
		resolverTextByID[id] = file.ResolverText
	}

	for idx := range state.ResolverProfiles {
		profile := state.ResolverProfiles[idx]
		resolverText, ok := resolverTextByID[profile.ID]
		if !ok {
			if strings.EqualFold(strings.TrimSpace(profile.ResolverSource), "file") {
				return model.AppState{}, fmt.Errorf("backup is missing resolver file contents for %q", profile.Name)
			}
			continue
		}

		dest := s.uniqueManagedResolverPathLocked(profile.ID)
		summary, err := normalizeResolverTextToManagedPath(resolverText, dest)
		if err != nil {
			return model.AppState{}, fmt.Errorf("restore resolver profile %q: %w", profile.Name, err)
		}
		if summary.Count == 0 {
			return model.AppState{}, fmt.Errorf("restore resolver profile %q: no valid resolvers", profile.Name)
		}

		profile.ResolverSource = "file"
		profile.ResolverFile = dest
		profile.ResolverText = ""
		profile.ResolverCount = summary.Count
		profile.ResolverPreview = summary.Preview
		profile.ResolverInvalidCount = summary.InvalidCount
		state.ResolverProfiles[idx] = profile
	}

	return state, nil
}
