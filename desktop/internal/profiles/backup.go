package profiles

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/resolver"
)

const (
	desktopBackupSchema  = "whitedns.desktop.backup"
	desktopBackupVersion = 2
)

type desktopBackup struct {
	Schema        string               `json:"schema"`
	Version       int                  `json:"version"`
	ExportedAt    string               `json:"exportedAt"`
	State         privateAppState      `json:"state"`
	ResolverFiles []backupResolverFile `json:"resolverFiles,omitempty"`
}

type backupResolverFile struct {
	ProfileID    string `json:"profileId"`
	ResolverText string `json:"resolverText"`
}

func (s *Store) ExportBackup(state model.AppState) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state.WhiteVPN = model.CloneWhiteVPNSettings(state.WhiteVPN)
	state = NormalizeState(state)
	backup := desktopBackup{
		Schema:     desktopBackupSchema,
		Version:    desktopBackupVersion,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		State:      privateAppState(state.BackupState()),
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
			ResolverText: resolver.NormalizeText(string(raw)),
		})
		backup.State.ResolverProfiles[idx].ResolverFile = ""
	}

	raw, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *Store) ImportBackup(rawText string) (result model.AppState, resultErr error) {
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
	if backup.Version != 1 && backup.Version != desktopBackupVersion {
		return model.AppState{}, fmt.Errorf("unsupported backup version")
	}
	var envelope struct {
		State json.RawMessage `json:"state"`
	}
	if err := json.Unmarshal([]byte(rawText), &envelope); err != nil || len(envelope.State) == 0 || strings.TrimSpace(string(envelope.State)) == "null" {
		return model.AppState{}, fmt.Errorf("backup state object is required")
	}
	if backup.Version == 2 {
		// Enforce the public schema even if an edited v2 backup supplies secrets.
		backup.State = privateAppState(model.AppState(backup.State).BackupState())
	}

	state, created, err := s.restoreBackupResolverFilesLocked(backup)
	committed := false
	defer func() {
		if !committed {
			for _, path := range created {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					resultErr = errors.Join(resultErr, fmt.Errorf("remove uncommitted resolver file: %w", err))
				}
			}
		}
	}()
	if err != nil {
		return model.AppState{}, err
	}
	state.Runtime = model.DefaultAppState().Runtime
	beforePaths := make(map[string]bool, len(state.ResolverProfiles))
	for _, p := range state.ResolverProfiles {
		beforePaths[p.ResolverFile] = true
	}
	state, _, err = s.prepareStateLocked(state, false)
	for _, p := range state.ResolverProfiles {
		if p.ResolverFile != "" && !beforePaths[p.ResolverFile] {
			created = append(created, p.ResolverFile)
		}
	}
	if err != nil {
		return model.AppState{}, err
	}
	if err := s.writeStateLocked(state); err != nil {
		return model.AppState{}, err
	}
	committed = true
	return state, nil
}

func (s *Store) restoreBackupResolverFilesLocked(backup desktopBackup) (model.AppState, []string, error) {
	state := model.AppState(backup.State)
	var created []string
	resolverTextByID := make(map[string]string, len(backup.ResolverFiles))
	for _, file := range backup.ResolverFiles {
		id := strings.TrimSpace(file.ProfileID)
		if id == "" {
			return model.AppState{}, created, fmt.Errorf("backup resolver file is missing a profile ID")
		}
		if _, exists := resolverTextByID[id]; exists {
			return model.AppState{}, created, fmt.Errorf("backup contains duplicate resolver file for %q", id)
		}
		resolverTextByID[id] = file.ResolverText
	}

	for idx := range state.ResolverProfiles {
		profile := state.ResolverProfiles[idx]
		resolverText, ok := resolverTextByID[profile.ID]
		if !ok {
			if strings.EqualFold(strings.TrimSpace(profile.ResolverSource), "file") {
				return model.AppState{}, created, fmt.Errorf("backup is missing resolver file contents for %q", profile.Name)
			}
			continue
		}

		dest := s.uniqueManagedResolverPathLocked(profile.ID)
		created = append(created, dest)
		summary, err := normalizeResolverTextToManagedPath(resolverText, dest)
		if err != nil {
			return model.AppState{}, created, fmt.Errorf("restore resolver profile %q: %w", profile.Name, err)
		}
		if summary.Count == 0 {
			return model.AppState{}, created, fmt.Errorf("restore resolver profile %q: no valid resolvers", profile.Name)
		}

		profile.ResolverSource = "file"
		profile.ResolverFile = dest
		profile.ResolverText = ""
		profile.ResolverCount = summary.Count
		profile.ResolverPreview = summary.Preview
		profile.ResolverInvalidCount = summary.InvalidCount
		state.ResolverProfiles[idx] = profile
	}

	return state, created, nil
}
