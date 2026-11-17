package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/unitronix/betterdesk-server/auth"
	"github.com/unitronix/betterdesk-server/crypto/peervault"
	"github.com/unitronix/betterdesk-server/db"
)

func TestDirectoryCorrelationAndLongestOUMapping(t *testing.T) {
	mappings, err := parseOUOrgMap("OU=Finance,DC=example,DC=com | org-finance\nOU=UK,OU=Finance,DC=example,DC=com | org-uk\n")
	if err != nil {
		t.Fatal(err)
	}
	entries := []auth.DirectoryEntry{
		{Kind: "computer", DN: "CN=PC01,OU=UK,OU=Finance,DC=example,DC=com", Name: "PC01", DNSHostName: "pc01.example.com", OU: "OU=UK,OU=Finance,DC=example,DC=com"},
		{Kind: "computer", DN: "CN=PC02,OU=Finance,DC=example,DC=com", Name: "PC02", OU: "OU=Finance,DC=example,DC=com"},
		{Kind: "user", DN: "CN=User,OU=Finance,DC=example,DC=com", Name: "User"},
	}
	peers := []*db.Peer{{ID: "peer-1", Hostname: "PC01"}, {ID: "peer-2", Hostname: "pc01.example.com"}}
	objects, summary := correlateDirectoryObjects(entries, peers, mappings)
	if summary.Ambiguous != 1 || summary.Unmatched != 1 || objects[0].MatchState != "ambiguous" {
		t.Fatalf("unexpected correlation summary: %+v / %+v", summary, objects[0])
	}
	if got := mappedOrgForOU(objects[0].OU, mappings); got != "org-uk" {
		t.Fatalf("longest OU mapping not selected: %s", got)
	}
	if got := normalizeDirectoryHost("PC01.Example.COM."); got != "pc01" {
		t.Fatalf("host normalization: %s", got)
	}
}

func TestManagedCredentialViewAndExpiryCleanup(t *testing.T) {
	database, err := db.OpenSQLite(filepath.Join(t.TempDir(), "managed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateOrganization(&db.Organization{ID: "org-1", Name: "Test"}); err != nil {
		t.Fatal(err)
	}
	peerID := "peer-view"
	if err := database.UpsertPeer(&db.Peer{ID: peerID, Hostname: "PC01", Status: "ONLINE"}); err != nil {
		t.Fatal(err)
	}
	if err := database.AssignDeviceToOrg(&db.OrgDevice{OrgID: "org-1", DeviceID: peerID}); err != nil {
		t.Fatal(err)
	}
	vault, err := peervault.New("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	password := "CorrectHorseBattery1234"
	nonce, ciphertext, keyID, err := vault.Seal(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveOrgPeerCredential(&db.OrgPeerCredential{OrgID: "org-1", PeerID: peerID, Nonce: nonce, Ciphertext: ciphertext, KeyID: keyID}); err != nil {
		t.Fatal(err)
	}
	credential := &db.ManagedCredential{OrgID: "org-1", PeerID: peerID, RequestID: "request-view", State: "active", Generation: 1, ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)}
	if err := database.SaveManagedCredential(credential); err != nil {
		t.Fatal(err)
	}
	server := &Server{db: database, peerVault: vault}
	request := httptest.NewRequest("GET", "/api/peers/"+peerID+"/managed-credential", nil)
	request.SetPathValue("id", "org-1")
	request.SetPathValue("peerId", peerID)
	response := httptest.NewRecorder()
	server.handleGetManagedCredential(response, request)
	if response.Code != 200 {
		t.Fatalf("view status %d: %s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["password"] != password || body["state"] != "active" {
		t.Fatalf("unexpected active credential response: %+v", body)
	}

	credential.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := database.SaveManagedCredential(credential); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest("GET", "/api/peers/"+peerID+"/managed-credential", nil)
	request.SetPathValue("id", "org-1")
	request.SetPathValue("peerId", peerID)
	response = httptest.NewRecorder()
	server.handleGetManagedCredential(response, request)
	body = map[string]any{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, exists := body["password"]; exists || body["state"] != "expired" {
		t.Fatalf("expired credential response leaked password: %+v", body)
	}
	server.expireManagedCredentials(time.Now().UTC())
	stored, err := database.GetOrgPeerCredential("org-1", peerID)
	if err != nil || stored != nil {
		t.Fatalf("expired vault row was not deleted: %+v, %v", stored, err)
	}
	storedManaged, err := database.GetManagedCredential("org-1", peerID)
	if err != nil || storedManaged == nil || storedManaged.State != "expired" {
		t.Fatalf("managed state was not expired: %+v, %v", storedManaged, err)
	}
}
