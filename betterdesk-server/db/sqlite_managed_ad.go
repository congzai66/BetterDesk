package db

import (
	"database/sql"
	"fmt"
	"strings"
)

func (s *SQLiteDB) migrateManagedAD() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS managed_credentials (
			org_id TEXT NOT NULL,
			peer_id TEXT NOT NULL,
			request_id TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL,
			generation INTEGER NOT NULL DEFAULT 0,
			expires_at TEXT NOT NULL DEFAULT '',
			updated_by TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (org_id, peer_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_managed_credentials_expiry ON managed_credentials(state, expires_at)`,
		`CREATE TABLE IF NOT EXISTS directory_objects (
			dn TEXT PRIMARY KEY,
			object_guid TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL,
			name TEXT NOT NULL DEFAULT '',
			sam_account_name TEXT NOT NULL DEFAULT '',
			dns_host_name TEXT NOT NULL DEFAULT '',
			ou TEXT NOT NULL DEFAULT '',
			peer_id TEXT NOT NULL DEFAULT '',
			org_id TEXT NOT NULL DEFAULT '',
			match_state TEXT NOT NULL DEFAULT '',
			last_seen_at TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_objects_kind_name ON directory_objects(kind, name)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_objects_peer ON directory_objects(peer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_objects_org ON directory_objects(org_id)`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("db: managed AD migration: %w", err)
		}
	}
	return nil
}

func (s *SQLiteDB) ensureManagedAD() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.migrateManagedAD()
}

func (s *SQLiteDB) SaveManagedCredential(c *ManagedCredential) error {
	if err := s.ensureManagedAD(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO managed_credentials
		(org_id, peer_id, request_id, state, generation, expires_at, updated_by, last_error, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
		ON CONFLICT(org_id, peer_id) DO UPDATE SET
		request_id=excluded.request_id, state=excluded.state, generation=excluded.generation,
		expires_at=excluded.expires_at, updated_by=excluded.updated_by, last_error=excluded.last_error,
		updated_at=datetime('now')`,
		c.OrgID, c.PeerID, c.RequestID, c.State, c.Generation, c.ExpiresAt, c.UpdatedBy, c.LastError)
	return err
}

func scanManagedCredential(row interface{ Scan(...any) error }) (*ManagedCredential, error) {
	var c ManagedCredential
	err := row.Scan(&c.OrgID, &c.PeerID, &c.RequestID, &c.State, &c.Generation,
		&c.ExpiresAt, &c.UpdatedBy, &c.LastError, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

const managedCredentialColumns = `org_id, peer_id, request_id, state, generation, expires_at, updated_by, last_error, created_at, updated_at`

func (s *SQLiteDB) GetManagedCredential(orgID, peerID string) (*ManagedCredential, error) {
	if err := s.ensureManagedAD(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return scanManagedCredential(s.db.QueryRow(`SELECT `+managedCredentialColumns+`
		FROM managed_credentials WHERE org_id=? AND peer_id=?`, orgID, peerID))
}

func (s *SQLiteDB) ListExpiredManagedCredentials(nowRFC3339 string, limit int) ([]*ManagedCredential, error) {
	if err := s.ensureManagedAD(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT `+managedCredentialColumns+` FROM managed_credentials
		WHERE state='active' AND expires_at!='' AND expires_at<=? ORDER BY expires_at LIMIT ?`, nowRFC3339, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ManagedCredential
	for rows.Next() {
		c, err := scanManagedCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteDB) DeleteManagedCredential(orgID, peerID string) error {
	if err := s.ensureManagedAD(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM managed_credentials WHERE org_id=? AND peer_id=?`, orgID, peerID)
	return err
}

func (s *SQLiteDB) ReplaceDirectoryObjects(objects []*DirectoryObject) error {
	if err := s.ensureManagedAD(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM directory_objects`); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO directory_objects
		(dn, object_guid, kind, name, sam_account_name, dns_host_name, ou, peer_id, org_id, match_state, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, o := range objects {
		if _, err := stmt.Exec(o.DN, o.ObjectGUID, o.Kind, o.Name, o.SamAccountName, o.DNSHostName,
			o.OU, o.PeerID, o.OrgID, o.MatchState, o.LastSeenAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteDB) ListDirectoryObjects(kind, query string, limit int) ([]*DirectoryObject, error) {
	if err := s.ensureManagedAD(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	where := []string{"1=1"}
	args := make([]any, 0, 4)
	if kind != "" {
		where = append(where, "kind=?")
		args = append(args, kind)
	}
	if q := strings.TrimSpace(query); q != "" {
		like := "%" + q + "%"
		where = append(where, "(name LIKE ? OR dn LIKE ? OR dns_host_name LIKE ? OR sam_account_name LIKE ?)")
		args = append(args, like, like, like, like)
	}
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT dn, object_guid, kind, name, sam_account_name, dns_host_name,
		ou, peer_id, org_id, match_state, last_seen_at FROM directory_objects
		WHERE `+strings.Join(where, " AND ")+` ORDER BY kind, name, dn LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*DirectoryObject, 0)
	for rows.Next() {
		var o DirectoryObject
		if err := rows.Scan(&o.DN, &o.ObjectGUID, &o.Kind, &o.Name, &o.SamAccountName, &o.DNSHostName,
			&o.OU, &o.PeerID, &o.OrgID, &o.MatchState, &o.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, &o)
	}
	return out, rows.Err()
}
