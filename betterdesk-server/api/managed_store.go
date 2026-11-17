package api

import "github.com/unitronix/betterdesk-server/db"

// These wrappers keep managed AD an optional database extension instead of
// widening BetterDesk's primary Database interface.
func (s *Server) managedADStore() (db.ManagedADStore, error) {
	return db.ManagedADStoreFor(s.db)
}

func (s *Server) SaveManagedCredential(c *db.ManagedCredential) error {
	store, err := s.managedADStore()
	if err != nil {
		return err
	}
	return store.SaveManagedCredential(c)
}

func (s *Server) GetManagedCredential(orgID, peerID string) (*db.ManagedCredential, error) {
	store, err := s.managedADStore()
	if err != nil {
		return nil, err
	}
	return store.GetManagedCredential(orgID, peerID)
}

func (s *Server) ListExpiredManagedCredentials(nowRFC3339 string, limit int) ([]*db.ManagedCredential, error) {
	store, err := s.managedADStore()
	if err != nil {
		return nil, err
	}
	return store.ListExpiredManagedCredentials(nowRFC3339, limit)
}

func (s *Server) DeleteManagedCredential(orgID, peerID string) error {
	store, err := s.managedADStore()
	if err != nil {
		return err
	}
	return store.DeleteManagedCredential(orgID, peerID)
}

func (s *Server) ReplaceDirectoryObjects(objects []*db.DirectoryObject) error {
	store, err := s.managedADStore()
	if err != nil {
		return err
	}
	return store.ReplaceDirectoryObjects(objects)
}

func (s *Server) ListDirectoryObjects(kind, query string, limit int) ([]*db.DirectoryObject, error) {
	store, err := s.managedADStore()
	if err != nil {
		return nil, err
	}
	return store.ListDirectoryObjects(kind, query, limit)
}
