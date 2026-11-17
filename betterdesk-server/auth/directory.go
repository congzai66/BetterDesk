package auth

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	directoryPageSize   = uint32(500)
	directoryMaxPerKind = 10000
)

// DirectoryEntry is an AD snapshot item. Sync is deliberately read-only.
type DirectoryEntry struct {
	DN             string
	ObjectGUID     string
	Kind           string
	Name           string
	SamAccountName string
	DNSHostName    string
	OU             string
	LastSeenAt     string
}

type directoryQuery struct {
	kind   string
	baseDN func(*LDAPConfig) string
	filter string
}

var directoryQueries = []directoryQuery{
	{kind: "user", baseDN: func(c *LDAPConfig) string { return c.BaseDN }, filter: "(&(objectClass=user)(!(objectClass=computer)))"},
	{kind: "group", baseDN: func(c *LDAPConfig) string {
		if c.GroupBaseDN != "" {
			return c.GroupBaseDN
		}
		return c.BaseDN
	}, filter: "(objectClass=group)"},
	{kind: "computer", baseDN: func(c *LDAPConfig) string { return c.BaseDN }, filter: "(objectClass=computer)"},
	{kind: "ou", baseDN: func(c *LDAPConfig) string { return c.BaseDN }, filter: "(objectClass=organizationalUnit)"},
}

// SyncDirectory reads AD users, groups, computers and OUs using the same
// authenticated LDAP configuration as login. It never writes to AD.
func connectAndBind(cfg *LDAPConfig) (*ldap.Conn, error) {
	if cfg.DirectBind {
		return nil, fmt.Errorf("directory synchronization requires bind+search mode with a read-only service account")
	}
	provider := NewLDAPProvider(cfg)
	conn, err := provider.dial(cfg)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func SyncDirectory(ctx context.Context, cfg *LDAPConfig) ([]DirectoryEntry, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("LDAP/AD is not enabled")
	}
	if strings.TrimSpace(cfg.BaseDN) == "" {
		return nil, fmt.Errorf("LDAP base DN is required")
	}
	conn, err := connectAndBind(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	out := make([]DirectoryEntry, 0)
	seen := make(map[string]bool)
	for _, query := range directoryQueries {
		baseDN := strings.TrimSpace(query.baseDN(cfg))
		if baseDN == "" {
			continue
		}
		if err := syncDirectoryKind(ctx, conn, baseDN, query, now, seen, &out); err != nil {
			return nil, fmt.Errorf("sync %s objects: %w", query.kind, err)
		}
	}
	return out, nil
}

func syncDirectoryKind(ctx context.Context, conn *ldap.Conn, baseDN string, query directoryQuery, now string, seen map[string]bool, out *[]DirectoryEntry) error {
	paging := ldap.NewControlPaging(directoryPageSize)
	count := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			query.filter,
			[]string{"distinguishedName", "objectGUID", "name", "cn", "sAMAccountName", "dNSHostName"},
			[]ldap.Control{paging})
		result, err := conn.Search(req)
		if err != nil {
			return err
		}
		for _, entry := range result.Entries {
			if count >= directoryMaxPerKind {
				return fmt.Errorf("object limit %d exceeded", directoryMaxPerKind)
			}
			item := directoryEntryFromLDAP(entry, query.kind, now)
			key := strings.ToLower(item.DN)
			if item.DN != "" && !seen[key] {
				seen[key] = true
				*out = append(*out, item)
				count++
			}
		}
		var cookie []byte
		for _, control := range result.Controls {
			if p, ok := control.(*ldap.ControlPaging); ok {
				cookie = p.Cookie
				break
			}
		}
		if len(cookie) == 0 {
			return nil
		}
		paging.SetCookie(cookie)
	}
}

func directoryEntryFromLDAP(entry *ldap.Entry, kind, now string) DirectoryEntry {
	dn := entry.DN
	name := entry.GetAttributeValue("name")
	if name == "" {
		name = entry.GetAttributeValue("cn")
	}
	return DirectoryEntry{
		DN: dn, ObjectGUID: formatADGUID(entry.GetRawAttributeValue("objectGUID")), Kind: kind,
		Name: name, SamAccountName: entry.GetAttributeValue("sAMAccountName"),
		DNSHostName: entry.GetAttributeValue("dNSHostName"), OU: directoryParentDN(dn), LastSeenAt: now,
	}
}

func directoryParentDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) < 2 {
		return ""
	}
	parent := *parsed
	parent.RDNs = parsed.RDNs[1:]
	return parent.String()
}

// formatADGUID converts Microsoft's little-endian GUID byte layout to text.
func formatADGUID(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	b := []byte{raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
