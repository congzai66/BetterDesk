package db

import "fmt"

// ManagedCredential tracks a server-issued, expiring RustDesk password.
// The plaintext is stored only in OrgPeerCredential's encrypted vault row.
type ManagedCredential struct {
	OrgID      string `json:"org_id"`
	PeerID     string `json:"peer_id"`
	RequestID  string `json:"request_id"`
	State      string `json:"state"` // pending, active, revoked, expired, failed
	Generation int64  `json:"generation"`
	ExpiresAt  string `json:"expires_at"`
	UpdatedBy  string `json:"updated_by,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

// DirectoryObject is a read-only snapshot of an AD user, group, computer or OU.
// PeerID and OrgID are local correlation results, not attributes read from AD.
type DirectoryObject struct {
	DN             string `json:"dn"`
	ObjectGUID     string `json:"object_guid"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	SamAccountName string `json:"sam_account_name,omitempty"`
	DNSHostName    string `json:"dns_host_name,omitempty"`
	OU             string `json:"ou,omitempty"`
	PeerID         string `json:"peer_id,omitempty"`
	OrgID          string `json:"org_id,omitempty"`
	MatchState     string `json:"match_state,omitempty"`
	LastSeenAt     string `json:"last_seen_at"`
}

// ManagedADStore is an optional extension implemented by both production
// databases. Keeping it separate avoids forcing third-party Database wrappers
// to implement unrelated AD methods during an upgrade.
type ManagedADStore interface {
	SaveManagedCredential(c *ManagedCredential) error
	GetManagedCredential(orgID, peerID string) (*ManagedCredential, error)
	ListExpiredManagedCredentials(nowRFC3339 string, limit int) ([]*ManagedCredential, error)
	DeleteManagedCredential(orgID, peerID string) error
	ReplaceDirectoryObjects(objects []*DirectoryObject) error
	ListDirectoryObjects(kind, query string, limit int) ([]*DirectoryObject, error)
}

// ManagedADStoreFor resolves the optional managed-AD extension.
func ManagedADStoreFor(database Database) (ManagedADStore, error) {
	store, ok := database.(ManagedADStore)
	if !ok {
		return nil, fmt.Errorf("db: managed AD store is not supported by %T", database)
	}
	return store, nil
}
