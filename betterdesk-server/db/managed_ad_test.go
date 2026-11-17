package db

import (
	"testing"
	"time"
)

func TestManagedCredentialLifecycleAndDirectoryCRUD(t *testing.T) {
	database := newTestDB(t)
	now := time.Now().UTC()
	expired := &ManagedCredential{OrgID: "org-1", PeerID: "peer-1", RequestID: "req-1", State: "active", Generation: 2, ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339), UpdatedBy: "tester"}
	future := &ManagedCredential{OrgID: "org-1", PeerID: "peer-2", RequestID: "req-2", State: "active", Generation: 1, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), UpdatedBy: "tester"}
	pending := &ManagedCredential{OrgID: "org-1", PeerID: "peer-3", RequestID: "req-3", State: "pending", Generation: 1, ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339), UpdatedBy: "tester"}
	for _, credential := range []*ManagedCredential{expired, future, pending} {
		if err := database.SaveManagedCredential(credential); err != nil {
			t.Fatalf("SaveManagedCredential: %v", err)
		}
	}
	rows, err := database.ListExpiredManagedCredentials(now.Format(time.RFC3339), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].PeerID != "peer-1" {
		t.Fatalf("unexpected expired credentials: %+v", rows)
	}
	got, err := database.GetManagedCredential("org-1", "peer-2")
	if err != nil || got == nil || got.Generation != 1 {
		t.Fatalf("GetManagedCredential: %+v, %v", got, err)
	}
	if err := database.DeleteManagedCredential("org-1", "peer-3"); err != nil {
		t.Fatal(err)
	}
	got, err = database.GetManagedCredential("org-1", "peer-3")
	if err != nil || got != nil {
		t.Fatalf("deleted credential still present: %+v, %v", got, err)
	}

	objects := []*DirectoryObject{
		{DN: "CN=PC01,OU=Finance,DC=example,DC=com", ObjectGUID: "guid-1", Kind: "computer", Name: "PC01", DNSHostName: "pc01.example.com", OU: "OU=Finance,DC=example,DC=com", PeerID: "peer-1", OrgID: "org-1", MatchState: "matched", LastSeenAt: now.Format(time.RFC3339)},
		{DN: "OU=Finance,DC=example,DC=com", Kind: "ou", Name: "Finance", LastSeenAt: now.Format(time.RFC3339)},
	}
	if err := database.ReplaceDirectoryObjects(objects); err != nil {
		t.Fatalf("ReplaceDirectoryObjects: %v", err)
	}
	computers, err := database.ListDirectoryObjects("computer", "pc01", 10)
	if err != nil || len(computers) != 1 || computers[0].PeerID != "peer-1" {
		t.Fatalf("ListDirectoryObjects: %+v, %v", computers, err)
	}
	if err := database.ReplaceDirectoryObjects([]*DirectoryObject{objects[1]}); err != nil {
		t.Fatal(err)
	}
	computers, err = database.ListDirectoryObjects("computer", "", 10)
	if err != nil || len(computers) != 0 {
		t.Fatalf("directory replacement did not remove stale computers: %+v, %v", computers, err)
	}
}
