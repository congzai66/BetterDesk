package api

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/unitronix/betterdesk-server/auth"
)

// managedRuntime keeps optional AD state out of BetterDesk's core Server
// structure. RegisterOnShutdown ties background workers to the normal API
// shutdown path without changing the upstream server lifecycle.
type managedRuntime struct {
	routesOnce      sync.Once
	servicesOnce    sync.Once
	routes          http.Handler
	directorySyncMu sync.Mutex
	credentialMu    sync.Mutex
	cancel          context.CancelFunc
}

var managedRuntimes sync.Map // map[*Server]*managedRuntime

func managedRuntimeFor(s *Server) *managedRuntime {
	runtime, _ := managedRuntimes.LoadOrStore(s, &managedRuntime{})
	return runtime.(*managedRuntime)
}

func isManagedAPIPath(path string) bool {
	if strings.HasPrefix(path, "/api/directory/") {
		return true
	}
	if strings.HasPrefix(path, "/api/peers/") && strings.HasSuffix(path, "/managed-credential") {
		return true
	}
	return strings.HasPrefix(path, "/api/org/") && strings.Contains(path, "/managed-credentials/")
}

func (s *Server) managedRoutes() http.Handler {
	runtime := managedRuntimeFor(s)
	runtime.routesOnce.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/org/{id}/managed-credentials/{peerId}", s.requirePermission(auth.PermCredentialView, s.requireOrgMembership("id", s.handleGetManagedCredential)))
		mux.HandleFunc("POST /api/org/{id}/managed-credentials/{peerId}", s.requirePermission(auth.PermCredentialRotate, s.requireOrgMembership("id", s.handleRotateManagedCredential)))
		mux.HandleFunc("DELETE /api/org/{id}/managed-credentials/{peerId}", s.requirePermission(auth.PermCredentialRotate, s.requireOrgMembership("id", s.handleRevokeManagedCredential)))
		mux.HandleFunc("GET /api/peers/{peerId}/managed-credential", s.requirePermission(auth.PermCredentialView, s.requireManagedCredentialOrg("peerId", s.handleGetManagedCredential)))
		mux.HandleFunc("POST /api/peers/{peerId}/managed-credential", s.requirePermission(auth.PermCredentialRotate, s.requireManagedCredentialOrg("peerId", s.handleRotateManagedCredential)))
		mux.HandleFunc("DELETE /api/peers/{peerId}/managed-credential", s.requirePermission(auth.PermCredentialRotate, s.requireManagedCredentialOrg("peerId", s.handleRevokeManagedCredential)))
		mux.HandleFunc("GET /api/directory/config", s.requirePermission(auth.PermDirectoryView, s.handleGetDirectoryConfig))
		mux.HandleFunc("PUT /api/directory/config", s.requirePermission(auth.PermDirectorySync, s.handleSaveDirectoryConfig))
		mux.HandleFunc("POST /api/directory/sync", s.requirePermission(auth.PermDirectorySync, s.handleDirectorySync))
		mux.HandleFunc("GET /api/directory/objects", s.requirePermission(auth.PermDirectoryView, s.handleListDirectoryObjects))
		runtime.routes = mux
	})
	return runtime.routes
}

func (s *Server) serveManagedAPI(w http.ResponseWriter, r *http.Request) bool {
	if !isManagedAPIPath(r.URL.Path) {
		return false
	}
	s.startManagedServices()
	s.authMiddleware(s.managedRoutes()).ServeHTTP(w, r)
	return true
}

func (s *Server) startManagedServices() {
	runtime := managedRuntimeFor(s)
	runtime.servicesOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		runtime.cancel = cancel
		if s.httpSrv != nil {
			s.httpSrv.RegisterOnShutdown(cancel)
		}
		s.wg.Add(2)
		go func() {
			defer s.wg.Done()
			s.directorySyncLoop(ctx)
		}()
		go func() {
			defer s.wg.Done()
			s.managedCredentialCleanupLoop(ctx)
		}()
	})
}
