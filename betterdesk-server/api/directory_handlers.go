package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/unitronix/betterdesk-server/audit"
	"github.com/unitronix/betterdesk-server/auth"
	"github.com/unitronix/betterdesk-server/db"
)

var errDirectorySyncRunning = errors.New("directory sync is already running")

type directorySettings struct {
	SyncIntervalMinutes int    `json:"sync_interval_minutes"`
	ApplyMappings       bool   `json:"apply_mappings"`
	OUOrgMap            string `json:"ou_org_map"`
	LastSyncAt          string `json:"last_sync_at,omitempty"`
	LastSyncStatus      string `json:"last_sync_status,omitempty"`
}

type directorySyncSummary struct {
	SyncedAt  string         `json:"synced_at"`
	Applied   bool           `json:"applied"`
	Total     int            `json:"total"`
	Counts    map[string]int `json:"counts"`
	Matched   int            `json:"matched"`
	Unmatched int            `json:"unmatched"`
	Ambiguous int            `json:"ambiguous"`
	Assigned  int            `json:"assigned"`
}

func (s *Server) loadDirectorySettings() directorySettings {
	settings := directorySettings{}
	if v, _ := s.db.GetConfig("ldap.sync_interval_minutes"); v != "" {
		settings.SyncIntervalMinutes, _ = strconv.Atoi(v)
	}
	applyValue, _ := s.db.GetConfig("ldap.sync_apply")
	settings.ApplyMappings = applyValue == "true"
	settings.OUOrgMap, _ = s.db.GetConfig("ldap.ou_org_map")
	settings.LastSyncAt, _ = s.db.GetConfig("ldap.sync_last_at")
	settings.LastSyncStatus, _ = s.db.GetConfig("ldap.sync_last_status")
	return settings
}

// parseOUOrgMap parses one "OU DN | organization ID" mapping per line.
func parseOUOrgMap(raw string) (map[string]string, error) {
	out := make(map[string]string)
	for lineNo, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("line %d: expected OU DN | organization ID", lineNo+1)
		}
		ou := normalizeDirectoryDN(parts[0])
		orgID := strings.TrimSpace(parts[1])
		if len(out) >= 256 && out[ou] == "" {
			return nil, fmt.Errorf("too many OU mappings (maximum 256)")
		}
		out[ou] = orgID
	}
	return out, nil
}

func normalizeDirectoryDN(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func mappedOrgForOU(ou string, mappings map[string]string) string {
	ou = normalizeDirectoryDN(ou)
	bestLen := -1
	orgID := ""
	for mappedOU, candidate := range mappings {
		if ou == mappedOU || strings.HasSuffix(ou, ","+mappedOU) {
			if len(mappedOU) > bestLen {
				bestLen = len(mappedOU)
				orgID = candidate
			}
		}
	}
	return orgID
}

func normalizeDirectoryHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
	if idx := strings.IndexByte(value, '.'); idx >= 0 {
		value = value[:idx]
	}
	return value
}

func correlateDirectoryObjects(entries []auth.DirectoryEntry, peers []*db.Peer, mappings map[string]string) ([]*db.DirectoryObject, directorySyncSummary) {
	byHost := make(map[string][]string)
	for _, peer := range peers {
		if host := normalizeDirectoryHost(peer.Hostname); host != "" {
			byHost[host] = append(byHost[host], peer.ID)
		}
	}
	summary := directorySyncSummary{Counts: make(map[string]int)}
	objects := make([]*db.DirectoryObject, 0, len(entries))
	for _, entry := range entries {
		o := &db.DirectoryObject{DN: entry.DN, ObjectGUID: entry.ObjectGUID, Kind: entry.Kind,
			Name: entry.Name, SamAccountName: entry.SamAccountName, DNSHostName: entry.DNSHostName,
			OU: entry.OU, LastSeenAt: entry.LastSeenAt}
		summary.Total++
		summary.Counts[o.Kind]++
		if o.Kind == "computer" {
			host := o.DNSHostName
			if host == "" {
				host = o.Name
			}
			matches := byHost[normalizeDirectoryHost(host)]
			switch len(matches) {
			case 0:
				o.MatchState = "unmatched"
				summary.Unmatched++
			case 1:
				o.MatchState = "matched"
				o.PeerID = matches[0]
				summary.Matched++
			default:
				o.MatchState = "ambiguous"
				summary.Ambiguous++
			}
			o.OrgID = mappedOrgForOU(o.OU, mappings)
		}
		objects = append(objects, o)
	}
	return objects, summary
}

func (s *Server) executeDirectorySync(ctx context.Context, apply bool) (*directorySyncSummary, error) {
	if !s.directorySyncMu.TryLock() {
		return nil, errDirectorySyncRunning
	}
	defer s.directorySyncMu.Unlock()

	entries, err := auth.SyncDirectory(ctx, s.loadLDAPConfigFromDB())
	if err != nil {
		_ = s.db.SetConfig("ldap.sync_last_status", "error")
		return nil, err
	}
	settings := s.loadDirectorySettings()
	mappings, err := parseOUOrgMap(settings.OUOrgMap)
	if err != nil {
		return nil, err
	}
	peers, err := s.db.ListPeers(false)
	if err != nil {
		return nil, err
	}
	objects, summary := correlateDirectoryObjects(entries, peers, mappings)
	summary.Applied = apply
	summary.SyncedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.ReplaceDirectoryObjects(objects); err != nil {
		return nil, err
	}
	if apply {
		for _, o := range objects {
			if o.Kind != "computer" || o.PeerID == "" || o.OrgID == "" {
				continue
			}
			org, err := s.db.GetOrganization(o.OrgID)
			if err != nil {
				return nil, err
			}
			if org == nil {
				return nil, fmt.Errorf("mapped organization %s does not exist", o.OrgID)
			}
			assignment := &db.OrgDevice{OrgID: o.OrgID, DeviceID: o.PeerID, Department: o.OU}
			existing, err := s.db.GetOrgDevice(o.OrgID, o.PeerID)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				assignment = existing
			}
			if err := s.db.AssignDeviceToOrg(assignment); err != nil {
				return nil, err
			}
			summary.Assigned++
		}
	}
	_ = s.db.SetConfig("ldap.sync_last_at", summary.SyncedAt)
	_ = s.db.SetConfig("ldap.sync_last_status", "ok")
	return &summary, nil
}

func (s *Server) handleGetDirectoryConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.loadDirectorySettings())
}

func (s *Server) handleSaveDirectoryConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireGlobalDirectoryManager(w, r) {
		return
	}
	var body directorySettings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}
	if body.SyncIntervalMinutes < 0 || body.SyncIntervalMinutes > 1440 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Sync interval must be between 0 and 1440 minutes"})
		return
	}
	mappings, err := parseOUOrgMap(body.OUOrgMap)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	for _, orgID := range mappings {
		org, err := s.db.GetOrganization(orgID)
		if err != nil || org == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Mapped organization does not exist: " + orgID})
			return
		}
	}
	for key, value := range map[string]string{
		"ldap.sync_interval_minutes": strconv.Itoa(body.SyncIntervalMinutes),
		"ldap.sync_apply":            strconv.FormatBool(body.ApplyMappings),
		"ldap.ou_org_map":            body.OUOrgMap,
	} {
		if err := s.db.SetConfig(key, value); err != nil {
			writeInternalError(w, err, "Save directory config")
			return
		}
	}
	s.auditLog.Log(audit.ActionConfigChanged, s.remoteIP(r), "ldap.directory", map[string]string{"sync": "configuration_updated"})
	writeJSON(w, http.StatusOK, s.loadDirectorySettings())
}

func (s *Server) requireGlobalDirectoryManager(w http.ResponseWriter, r *http.Request) bool {
	role := getRoleFromCtx(r)
	if auth.IsSuperAdminRole(role) || role == auth.RoleGlobalAdmin || role == auth.RoleServerAdmin {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "Global directory administrator required"})
	return false
}

func (s *Server) handleDirectorySync(w http.ResponseWriter, r *http.Request) {
	if !s.requireGlobalDirectoryManager(w, r) {
		return
	}
	settings := s.loadDirectorySettings()
	var body struct {
		Apply *bool `json:"apply"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
			return
		}
	}
	apply := settings.ApplyMappings
	if body.Apply != nil {
		apply = *body.Apply
	}
	summary, err := s.executeDirectorySync(r.Context(), apply)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errDirectorySyncRunning) {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog.Log(audit.ActionDirectorySync, s.remoteIP(r), "ldap.directory", map[string]string{
		"applied": strconv.FormatBool(apply), "total": strconv.Itoa(summary.Total), "assigned": strconv.Itoa(summary.Assigned),
	})
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleListDirectoryObjects(w http.ResponseWriter, r *http.Request) {
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kind != "" && kind != "user" && kind != "group" && kind != "computer" && kind != "ou" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid directory object kind"})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	objects, err := s.ListDirectoryObjects(kind, r.URL.Query().Get("q"), limit)
	if err != nil {
		writeInternalError(w, err, "List directory objects")
		return
	}
	orgID := getOrgIDFromCtx(r)
	if orgID != "" {
		filtered := make([]*db.DirectoryObject, 0, len(objects))
		for _, o := range objects {
			if o.OrgID == orgID {
				filtered = append(filtered, o)
			}
		}
		objects = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": objects, "count": len(objects)})
}

func (s *Server) directorySyncLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			settings := s.loadDirectorySettings()
			if settings.SyncIntervalMinutes <= 0 {
				continue
			}
			due := settings.LastSyncAt == ""
			if last, err := time.Parse(time.RFC3339, settings.LastSyncAt); err == nil {
				due = time.Since(last) >= time.Duration(settings.SyncIntervalMinutes)*time.Minute
			}
			if !due {
				continue
			}
			if summary, err := s.executeDirectorySync(ctx, settings.ApplyMappings); err != nil {
				if !errors.Is(err, errDirectorySyncRunning) {
					log.Printf("[directory] scheduled sync failed: %v", err)
				}
			} else {
				s.auditLog.Log(audit.ActionDirectorySync, "system", "ldap.directory", map[string]string{
					"applied": strconv.FormatBool(summary.Applied), "total": strconv.Itoa(summary.Total), "assigned": strconv.Itoa(summary.Assigned),
				})
			}
		}
	}
}
