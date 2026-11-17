package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/unitronix/betterdesk-server/audit"
	"github.com/unitronix/betterdesk-server/cdap"
	"github.com/unitronix/betterdesk-server/db"
)

const (
	managedCredentialWidget       = "betterdesk.managed_credential"
	defaultManagedCredentialTTL   = 15
	maxManagedCredentialTTL       = 120
	managedCredentialCommandWait  = 20 * time.Second
	managedCredentialPasswordSize = 24
)

func managedCredentialUsable(c *db.ManagedCredential, now time.Time) bool {
	if c == nil || c.State != "active" {
		return false
	}
	expires, err := time.Parse(time.RFC3339, c.ExpiresAt)
	return err == nil && now.Before(expires)
}

func generateManagedPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	out := make([]byte, managedCredentialPasswordSize)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}

func (s *Server) requireManagedCredentialOrg(peerParam string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID, err := s.db.GetDeviceOrgID(r.PathValue(peerParam))
		if err != nil {
			writeInternalError(w, err, "Resolve managed credential organization")
			return
		}
		if orgID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer is not assigned to an organization"})
			return
		}
		r.SetPathValue("id", orgID)
		s.requireOrgMembership("id", handler)(w, r)
	}
}

func (s *Server) validateManagedCredentialTarget(orgID, peerID string) error {
	if !peerIDRegexp.MatchString(peerID) {
		return errors.New("invalid peer ID")
	}
	peer, err := s.db.GetPeer(peerID)
	if err != nil {
		return err
	}
	if peer == nil || peer.SoftDeleted || peer.Banned {
		return errors.New("active peer not found")
	}
	assignment, err := s.db.GetOrgDevice(orgID, peerID)
	if err != nil {
		return err
	}
	if assignment == nil {
		return errors.New("peer is not assigned to this organization")
	}
	return nil
}

func (s *Server) managedCredentialTransportReady() bool {
	return s != nil && s.cdapGw != nil && s.peerVault != nil && s.cfg != nil && s.cfg.CDAPTLSEnabled()
}

func (s *Server) handleGetManagedCredential(w http.ResponseWriter, r *http.Request) {
	orgID, peerID := r.PathValue("id"), r.PathValue("peerId")
	if err := s.validateManagedCredentialTarget(orgID, peerID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	credential, err := s.GetManagedCredential(orgID, peerID)
	if err != nil {
		writeInternalError(w, err, "Get managed credential")
		return
	}
	if credential == nil {
		writeJSON(w, http.StatusOK, map[string]any{"managed": false, "state": "none"})
		return
	}
	if credential.State == "active" && !managedCredentialUsable(credential, time.Now().UTC()) {
		credential.State = "expired"
	}
	result := map[string]any{
		"managed": true, "state": credential.State, "status": credential.State,
		"request_id": credential.RequestID, "generation": credential.Generation,
		"expires_at": credential.ExpiresAt, "last_error": credential.LastError,
	}
	if managedCredentialUsable(credential, time.Now().UTC()) {
		if s.peerVault == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "peer credential vault not configured"})
			return
		}
		row, err := s.db.GetOrgPeerCredential(orgID, peerID)
		if err != nil {
			writeInternalError(w, err, "Read managed credential vault")
			return
		}
		if row == nil || row.Ciphertext == "" {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "active managed credential has no vault entry"})
			return
		}
		plain, err := s.peerVault.Open(row.Nonce, row.Ciphertext, row.KeyID)
		if err != nil {
			writeInternalError(w, err, "Decrypt managed credential")
			return
		}
		result["password"] = plain
		if s.auditLog != nil {
			s.auditLog.Log(audit.ActionOrgPeerCredentialFetch, s.remoteIP(r), peerID, map[string]string{
				"org_id": orgID, "actor": getUsernameFromCtx(r), "managed": "true", "request_id": credential.RequestID,
			})
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRotateManagedCredential(w http.ResponseWriter, r *http.Request) {
	managedRuntimeFor(s).credentialMu.Lock()
	defer managedRuntimeFor(s).credentialMu.Unlock()
	orgID, peerID := r.PathValue("id"), r.PathValue("peerId")
	username := getUsernameFromCtx(r)
	if username == "" {
		username = "api"
	}
	if err := s.validateManagedCredentialTarget(orgID, peerID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if !s.managedCredentialTransportReady() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Managed credentials require CDAP with TLS and the encrypted peer vault"})
		return
	}
	var body struct {
		TTLMinutes int `json:"ttl_minutes"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
			return
		}
	}
	if body.TTLMinutes == 0 {
		body.TTLMinutes = defaultManagedCredentialTTL
	}
	if body.TTLMinutes < 5 || body.TTLMinutes > maxManagedCredentialTTL {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "TTL must be between 5 and 120 minutes"})
		return
	}
	previous, err := s.GetManagedCredential(orgID, peerID)
	if err != nil {
		writeInternalError(w, err, "Read previous managed credential")
		return
	}
	generation := int64(1)
	if previous != nil {
		generation = previous.Generation + 1
	}
	password, err := generateManagedPassword()
	if err != nil {
		writeInternalError(w, err, "Generate managed credential")
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(body.TTLMinutes) * time.Minute).Truncate(time.Second)
	credential := &db.ManagedCredential{
		OrgID: orgID, PeerID: peerID, RequestID: uuid.NewString(), State: "pending",
		Generation: generation, ExpiresAt: expiresAt.Format(time.RFC3339), UpdatedBy: username,
	}
	if err := s.SaveManagedCredential(credential); err != nil {
		writeInternalError(w, err, "Create pending managed credential")
		return
	}
	commandPayload, err := json.Marshal(cdap.CommandPayload{
		CommandID: credential.RequestID, WidgetID: managedCredentialWidget, Action: "rotate",
		Value:    map[string]any{"password": password, "expires_at": credential.ExpiresAt, "request_id": credential.RequestID},
		Operator: username, Reason: "server-managed temporary credential",
	})
	if err != nil {
		writeInternalError(w, err, "Encode managed credential command")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), managedCredentialCommandWait)
	defer cancel()
	response, commandErr := s.cdapGw.SendCommandAndWait(ctx, peerID, &cdap.CommandMessage{ID: credential.RequestID, Payload: commandPayload})
	if commandErr != nil || response == nil || response.Status != "ok" {
		credential.State = "failed"
		if commandErr != nil {
			credential.LastError = sanitizeManagedCredentialError(commandErr.Error())
		} else if response != nil {
			credential.LastError = sanitizeManagedCredentialError(response.ErrorMessage)
		}
		_ = s.db.DeleteOrgPeerCredential(orgID, peerID)
		_ = s.SaveManagedCredential(credential)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "Agent did not confirm the password rotation", "request_id": credential.RequestID})
		return
	}
	nonce, ciphertext, keyID, err := s.peerVault.Seal(password)
	if err != nil {
		writeInternalError(w, err, "Encrypt managed credential")
		return
	}
	if err := s.db.SaveOrgPeerCredential(&db.OrgPeerCredential{OrgID: orgID, PeerID: peerID,
		Nonce: nonce, Ciphertext: ciphertext, KeyID: keyID, UpdatedBy: username}); err != nil {
		writeInternalError(w, err, "Save managed credential")
		return
	}
	credential.State = "active"
	credential.LastError = ""
	if err := s.SaveManagedCredential(credential); err != nil {
		writeInternalError(w, err, "Activate managed credential")
		return
	}
	s.auditLog.Log(audit.ActionManagedCredentialRotate, s.remoteIP(r), peerID, map[string]string{
		"org_id": orgID, "request_id": credential.RequestID, "generation": fmt.Sprintf("%d", generation),
		"ttl_minutes": fmt.Sprintf("%d", body.TTLMinutes), "operator": username,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"managed": true, "state": credential.State, "request_id": credential.RequestID,
		"generation": generation, "password": password, "expires_at": credential.ExpiresAt,
	})
}

func sanitizeManagedCredentialError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 256 {
		value = value[:256]
	}
	return value
}

func (s *Server) handleRevokeManagedCredential(w http.ResponseWriter, r *http.Request) {
	managedRuntimeFor(s).credentialMu.Lock()
	defer managedRuntimeFor(s).credentialMu.Unlock()
	orgID, peerID := r.PathValue("id"), r.PathValue("peerId")
	if err := s.validateManagedCredentialTarget(orgID, peerID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if !s.managedCredentialTransportReady() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Managed credentials require an online CDAP TLS agent"})
		return
	}
	credential, err := s.GetManagedCredential(orgID, peerID)
	if err != nil || credential == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Managed credential not found"})
		return
	}
	requestID := uuid.NewString()
	commandPayload, err := json.Marshal(cdap.CommandPayload{CommandID: requestID, WidgetID: managedCredentialWidget, Action: "revoke",
		Value: map[string]any{"request_id": requestID}, Operator: getUsernameFromCtx(r), Reason: "managed credential revoked"})
	if err != nil {
		writeInternalError(w, err, "Encode credential revocation command")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), managedCredentialCommandWait)
	defer cancel()
	response, commandErr := s.cdapGw.SendCommandAndWait(ctx, peerID, &cdap.CommandMessage{ID: requestID, Payload: commandPayload})
	if commandErr != nil || response == nil || response.Status != "ok" {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Agent did not confirm credential revocation"})
		return
	}
	if err := s.db.DeleteOrgPeerCredential(orgID, peerID); err != nil {
		writeInternalError(w, err, "Delete revoked managed credential")
		return
	}
	credential.State = "revoked"
	credential.RequestID = requestID
	credential.LastError = ""
	credential.ExpiresAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.SaveManagedCredential(credential); err != nil {
		writeInternalError(w, err, "Save revoked managed credential")
		return
	}
	s.auditLog.Log(audit.ActionManagedCredentialRevoke, s.remoteIP(r), peerID, map[string]string{"org_id": orgID, "request_id": requestID})
	writeJSON(w, http.StatusOK, map[string]any{"managed": true, "state": "revoked", "request_id": requestID})
}

func (s *Server) expireManagedCredentials(now time.Time) {
	credentials, err := s.ListExpiredManagedCredentials(now.UTC().Format(time.RFC3339), 500)
	if err != nil {
		log.Printf("[credentials] expiry query failed: %v", err)
		return
	}
	for _, credential := range credentials {
		if err := s.db.DeleteOrgPeerCredential(credential.OrgID, credential.PeerID); err != nil {
			log.Printf("[credentials] failed to remove expired vault row for peer %s: %v", credential.PeerID, err)
			continue
		}
		credential.State = "expired"
		if err := s.SaveManagedCredential(credential); err != nil {
			log.Printf("[credentials] failed to save expired state for peer %s: %v", credential.PeerID, err)
			continue
		}
		if s.auditLog != nil {
			s.auditLog.Log(audit.ActionManagedCredentialExpire, "system", credential.PeerID, map[string]string{
				"org_id": credential.OrgID, "request_id": credential.RequestID,
			})
		}
	}
}

func (s *Server) managedCredentialCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.expireManagedCredentials(now)
		}
	}
}
