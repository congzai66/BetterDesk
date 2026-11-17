package db

import (
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (pg *PostgresDB) migrateManagedAD() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS managed_credentials (
			org_id TEXT NOT NULL,
			peer_id TEXT NOT NULL,
			request_id TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL,
			generation BIGINT NOT NULL DEFAULT 0,
			expires_at TEXT NOT NULL DEFAULT '',
			updated_by TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
			updated_at TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
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
		if _, err := pg.pool.Exec(pg.ctx, stmt); err != nil {
			return fmt.Errorf("db: managed AD migration: %w", err)
		}
	}
	return nil
}

func (pg *PostgresDB) SaveManagedCredential(c *ManagedCredential) error {
	_, err := pg.pool.Exec(pg.ctx, `INSERT INTO managed_credentials
		(org_id, peer_id, request_id, state, generation, expires_at, updated_by, last_error)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT(org_id, peer_id) DO UPDATE SET
		request_id=EXCLUDED.request_id, state=EXCLUDED.state, generation=EXCLUDED.generation,
		expires_at=EXCLUDED.expires_at, updated_by=EXCLUDED.updated_by, last_error=EXCLUDED.last_error,
		updated_at=to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`, c.OrgID, c.PeerID, c.RequestID, c.State, c.Generation, c.ExpiresAt, c.UpdatedBy, c.LastError)
	return err
}

func (pg *PostgresDB) GetManagedCredential(orgID, peerID string) (*ManagedCredential, error) {
	var c ManagedCredential
	err := pg.pool.QueryRow(pg.ctx, `SELECT `+managedCredentialColumns+`
		FROM managed_credentials WHERE org_id=$1 AND peer_id=$2`, orgID, peerID).Scan(
		&c.OrgID, &c.PeerID, &c.RequestID, &c.State, &c.Generation, &c.ExpiresAt,
		&c.UpdatedBy, &c.LastError, &c.CreatedAt, &c.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (pg *PostgresDB) ListExpiredManagedCredentials(nowRFC3339 string, limit int) ([]*ManagedCredential, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := pg.pool.Query(pg.ctx, `SELECT `+managedCredentialColumns+` FROM managed_credentials
		WHERE state='active' AND expires_at!='' AND expires_at<=$1 ORDER BY expires_at LIMIT $2`, nowRFC3339, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ManagedCredential
	for rows.Next() {
		var c ManagedCredential
		if err := rows.Scan(&c.OrgID, &c.PeerID, &c.RequestID, &c.State, &c.Generation,
			&c.ExpiresAt, &c.UpdatedBy, &c.LastError, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (pg *PostgresDB) DeleteManagedCredential(orgID, peerID string) error {
	_, err := pg.pool.Exec(pg.ctx, `DELETE FROM managed_credentials WHERE org_id=$1 AND peer_id=$2`, orgID, peerID)
	return err
}

func (pg *PostgresDB) ReplaceDirectoryObjects(objects []*DirectoryObject) error {
	tx, err := pg.pool.Begin(pg.ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(pg.ctx)
	if _, err := tx.Exec(pg.ctx, `DELETE FROM directory_objects`); err != nil {
		return err
	}
	for _, o := range objects {
		if _, err := tx.Exec(pg.ctx, `INSERT INTO directory_objects
			(dn, object_guid, kind, name, sam_account_name, dns_host_name, ou, peer_id, org_id, match_state, last_seen_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, o.DN, o.ObjectGUID, o.Kind, o.Name,
			o.SamAccountName, o.DNSHostName, o.OU, o.PeerID, o.OrgID, o.MatchState, o.LastSeenAt); err != nil {
			return err
		}
	}
	return tx.Commit(pg.ctx)
}

func (pg *PostgresDB) ListDirectoryObjects(kind, query string, limit int) ([]*DirectoryObject, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	where := []string{"1=1"}
	args := make([]any, 0, 6)
	if kind != "" {
		args = append(args, kind)
		where = append(where, fmt.Sprintf("kind=$%d", len(args)))
	}
	if q := strings.TrimSpace(query); q != "" {
		like := "%" + q + "%"
		args = append(args, like, like, like, like)
		n := len(args) - 3
		where = append(where, fmt.Sprintf("(name ILIKE $%d OR dn ILIKE $%d OR dns_host_name ILIKE $%d OR sam_account_name ILIKE $%d)", n, n+1, n+2, n+3))
	}
	args = append(args, limit)
	rows, err := pg.pool.Query(pg.ctx, `SELECT dn, object_guid, kind, name, sam_account_name, dns_host_name,
		ou, peer_id, org_id, match_state, last_seen_at FROM directory_objects WHERE `+strings.Join(where, " AND ")+
		fmt.Sprintf(` ORDER BY kind, name, dn LIMIT $%d`, len(args)), args...)
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
